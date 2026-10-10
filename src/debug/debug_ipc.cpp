/*
 *  Copyright (C) 2002-2026  The DOSBox Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1110, USA.
 */

/* Debugger IPC server implementation. Transport contract:
 *   - listen on 127.0.0.1 only, single client, sequential commands;
 *   - requests and responses/events are one JSON object per line
 *     ('\n' delimited), correlated by "id" (events use id 0);
 *   - requests are only executed while the debugger is active (guest
 *     stopped); bytes sent while the guest runs wait in the socket
 *     buffer and are processed at the next stop;
 *   - responses/events are queued in a finite buffer and flushed with
 *     non-blocking sends; buffer overflow drops the client;
 *   - the flat-object parser accepts string and integer values only,
 *     without escape sequences (field values are identifiers/numbers).
 * Numeric request fields are hexadecimal unless noted (len is decimal
 * or 0x-prefixed). */

/* Winsock must come in before anything that pulls in windows.h. */
#if defined(WIN32)
# define WIN32_LEAN_AND_MEAN
# include <winsock2.h>
# include <ws2tcpip.h>
#endif

#include "dosbox.h"

#if C_DEBUG

#include "debug_ipc.h"

#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstring>
#include <map>
#include <string>

#include <SDL.h> /* SDL_CreateThread / SDL_Delay */
#include "cpu.h"
#include "mem.h"
#include "paging.h" /* mem_readb_checked */
#include "../cpu/lazyflags.h"
#include "logging.h"
#include "mouse.h"

extern void Mouse_SetClientCursorPos(int16_t x, int16_t y);

/* debug.cpp globals (codebase pattern: local extern declarations). */
extern uint64_t GetAddress(uint16_t seg, uint32_t offset);

/* savestates.cpp globals (codebase pattern: local extern declarations). */
extern size_t GetGameState_Run(void);
extern void SetGameState_Run(int value);
extern bool noremark_save_state;

#if !defined(WIN32)
# include <sys/types.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <netinet/tcp.h>
# include <arpa/inet.h>
# include <unistd.h>
# include <fcntl.h>
# include <errno.h>
#endif

/* ------------------------------------------------------------------ */
/* Socket layer                                                        */
/* ------------------------------------------------------------------ */

#if defined(WIN32)
typedef SOCKET ipc_sock_t;
# define IPC_BAD_SOCKET INVALID_SOCKET
static bool ipc_wsa_up = false;
#else
typedef int ipc_sock_t;
# define IPC_BAD_SOCKET (-1)
#endif

static ipc_sock_t listen_socket = IPC_BAD_SOCKET;
static ipc_sock_t client_socket = IPC_BAD_SOCKET;

/* v1.1 forced-stop channel: dedicated listener + background thread that
 * only honors "break_request" lines. GFX_Events() polls the flag (see
 * DEBUG_IPC_BreakRequested) and stops the guest via DEBUG_EnableDebugger,
 * replacing the Alt+F12/GameLink key injection path. */
static ipc_sock_t break_listen_socket = IPC_BAD_SOCKET;
static volatile int ipc_break_flag = 0;
static int ipc_break_thread(void*); /* defined after the JSON parser */

static const size_t IPC_MAX_OUTBUF = 4u * 1024u * 1024u; /* send buffer cap */
static const size_t IPC_MAX_LINE   = 1024u * 1024u;      /* request line cap */
static const unsigned long long IPC_MEMREAD_MAX = 65536ull; /* v1 read cap */

static std::string inbuf;  /* partial request line from the client */
static std::string outbuf; /* pending response/event bytes */

/* Set at each debugger entry point (see DEBUG_IPC_SetStopReason). */
static const char* ipc_stop_reason = "unknown";

static void ipc_close_sock(ipc_sock_t s) {
#if defined(WIN32)
    closesocket(s);
#else
    close(s);
#endif
}

static bool ipc_set_nonblocking(ipc_sock_t s) {
#if defined(WIN32)
    u_long mode = 1;
    return ioctlsocket(s, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(s, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
#endif
}

static bool ipc_would_block(void) {
#if defined(WIN32)
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static void ipc_disconnect_client(void) {
    if (client_socket != IPC_BAD_SOCKET) {
        ipc_close_sock(client_socket);
        client_socket = IPC_BAD_SOCKET;
        LOG_MSG("DEBUG_IPC: client disconnected");
    }
    inbuf.clear();
    outbuf.clear();
}

void DEBUG_IPC_StartUp(int port, int break_port) {
    if (listen_socket != IPC_BAD_SOCKET)
        return; /* already started */

#if defined(WIN32)
    if (!ipc_wsa_up) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
            LOG_MSG("DEBUG_IPC: WSAStartup failed, server disabled");
            return;
        }
        ipc_wsa_up = true;
    }
#endif

    ipc_sock_t s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == IPC_BAD_SOCKET) {
        LOG_MSG("DEBUG_IPC: socket() failed, server disabled");
        return;
    }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(s, 1) != 0 || !ipc_set_nonblocking(s)) {
        LOG_MSG("DEBUG_IPC: bind/listen on 127.0.0.1 failed, server disabled");
        ipc_close_sock(s);
        return;
    }

    struct sockaddr_in bound;
    memset(&bound, 0, sizeof(bound));
    socklen_t blen = sizeof(bound);
    unsigned short real_port = (unsigned short)port;
    if (getsockname(s, (struct sockaddr*)&bound, &blen) == 0)
        real_port = ntohs(bound.sin_port);

    listen_socket = s;
    LOG_MSG("DEBUG_IPC: debugger IPC listening on 127.0.0.1:%u "
            "(connect while the guest is stopped)",
            (unsigned)real_port);

    /* Dedicated forced-stop channel (v1.1): own listener + thread so a
     * break_request can be serviced while the guest is running. */
    ipc_sock_t b = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (b == IPC_BAD_SOCKET)
        return;
    setsockopt(b, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof(one));
    addr.sin_port = htons((unsigned short)break_port);
    if (bind(b, (struct sockaddr*)&addr, sizeof(addr)) != 0 ||
        listen(b, 1) != 0) {
        LOG_MSG("DEBUG_IPC: break channel bind/listen failed (forced stop disabled)");
        ipc_close_sock(b);
        return;
    }
    unsigned short real_break_port = (unsigned short)break_port;
    if (getsockname(b, (struct sockaddr*)&bound, &blen) == 0)
        real_break_port = ntohs(bound.sin_port);
    break_listen_socket = b;
    LOG_MSG("DEBUG_IPC: break channel listening on 127.0.0.1:%u "
            "(send {\"cmd\":\"break_request\"} to force a stop)",
            (unsigned)real_break_port);
    SDL_Thread* thread = SDL_CreateThread(ipc_break_thread, "dbgipc_brk", nullptr);
    if (thread == nullptr) {
        LOG_MSG("DEBUG_IPC: break thread spawn failed (forced stop disabled)");
        ipc_close_sock(break_listen_socket);
        break_listen_socket = IPC_BAD_SOCKET;
        return;
    }
    SDL_DetachThread(thread);
}

static void ipc_try_accept(void) {
    if (listen_socket == IPC_BAD_SOCKET || client_socket != IPC_BAD_SOCKET)
        return;

    ipc_sock_t c = accept(listen_socket, nullptr, nullptr);
    if (c == IPC_BAD_SOCKET)
        return; /* nothing pending or transient error */

    if (!ipc_set_nonblocking(c)) {
        ipc_close_sock(c);
        return;
    }
    int one = 1;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, (const char*)&one, sizeof(one));

    client_socket = c;
    inbuf.clear();
    outbuf.clear();
    LOG_MSG("DEBUG_IPC: client connected");
}

static void ipc_flush(void) {
    if (client_socket == IPC_BAD_SOCKET) {
        outbuf.clear();
        return;
    }
    while (!outbuf.empty()) {
        int n = (int)send(client_socket, outbuf.data(),
                          (int)outbuf.size(), 0);
        if (n > 0) {
            outbuf.erase(0, (size_t)n);
            continue;
        }
        if (n < 0 && ipc_would_block())
            return;
        ipc_disconnect_client();
        return;
    }
}

static void ipc_send_line(const std::string& line) {
    if (client_socket == IPC_BAD_SOCKET)
        return;
    if (outbuf.size() + line.size() > IPC_MAX_OUTBUF) {
        LOG_MSG("DEBUG_IPC: output buffer overflow, dropping client");
        ipc_disconnect_client();
        return;
    }
    outbuf += line;
    ipc_flush();
}

static void ipc_recv_requests(void) {
    char chunk[8192];
    for (;;) {
        int n = (int)recv(client_socket, chunk, sizeof(chunk), 0);
        if (n > 0) {
            inbuf.append(chunk, (size_t)n);
            if (inbuf.size() > IPC_MAX_LINE) {
                LOG_MSG("DEBUG_IPC: request line too long, dropping client");
                ipc_disconnect_client();
                return;
            }
            continue;
        }
        if (n == 0) { /* orderly shutdown */
            ipc_disconnect_client();
            return;
        }
        if (ipc_would_block())
            return;
        ipc_disconnect_client();
        return;
    }
}

/* ------------------------------------------------------------------ */
/* Minimal flat-object JSON request parser                             */
/* ------------------------------------------------------------------ */

struct IpcRequest {
    long long id = 0;
    std::string cmd;
    std::map<std::string, std::string> args;
};

static bool ipc_parse_request(const char* s, IpcRequest& req) {
    while (*s == ' ' || *s == '\t') s++;
    if (*s != '{') return false;
    s++;
    for (;;) {
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '}')
            break;
        if (*s != '"') return false;
        std::string key;
        s++;
        while (*s && *s != '"') {
            if (*s == '\\') return false; /* escapes unsupported */
            key += *s++;
        }
        if (*s != '"') return false;
        s++;
        while (*s == ' ' || *s == '\t') s++;
        if (*s != ':') return false;
        s++;
        while (*s == ' ' || *s == '\t') s++;
        std::string val;
        if (*s == '"') {
            s++;
            while (*s && *s != '"') {
                if (*s == '\\') return false;
                val += *s++;
            }
            if (*s != '"') return false;
            s++;
        }
        else {
            while ((*s >= '0' && *s <= '9') || *s == '-' || *s == '+')
                val += *s++;
            if (val.empty()) return false;
        }
        if (key == "id")
            req.id = strtoll(val.c_str(), nullptr, 10);
        else if (key == "cmd")
            req.cmd = val;
        else
            req.args[key] = val;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == ',') {
            s++;
            continue;
        }
        if (*s == '}')
            break;
        return false;
    }
    return !req.cmd.empty();
}

/* Hex field: accepts optional 0x prefix (strtoul base 16 also takes a
 * bare 0x). Used for seg/off/int/ah/al/bp ids and "addr". */
static bool ipc_hex(const std::string& s, unsigned long long* out) {
    if (s.empty()) return false;
    char* end = nullptr;
    unsigned long long v = strtoull(s.c_str(), &end, 16);
    if (end == s.c_str() || *end != '\0') return false;
    *out = v;
    return true;
}

/* Length field: decimal, or 0x-prefixed hex. */
static bool ipc_uint(const std::string& s, unsigned long long* out) {
    if (s.empty()) return false;
    int base = 10;
    const char* p = s.c_str();
    if (s.size() > 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        base = 16;
        p += 2;
    }
    char* end = nullptr;
    unsigned long long v = strtoull(p, &end, base);
    if (end == p || *end != '\0') return false;
    *out = v;
    return true;
}

/* Optional/required argument lookup for const requests. */
static const std::string* ipc_arg(const IpcRequest& req, const char* key) {
    auto it = req.args.find(key);
    return it == req.args.end() ? nullptr : &it->second;
}

/* ---- v1.1 break_request listener (needs the parser above) ---- */

static int ipc_break_thread(void*) {
    /* Blocking accept is fine here: this socket serves only short-lived
     * break_request connections while the main loop keeps its own single
     * client on the command port. */
    for (;;) {
        ipc_sock_t c = accept(break_listen_socket, nullptr, nullptr);
        if (c == IPC_BAD_SOCKET) {
            SDL_Delay(50);
            continue;
        }
        /* One request line, bounded wait. */
#if defined(WIN32)
        DWORD ms = 5000;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&ms, sizeof(ms));
#else
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
        std::string line;
        char chunk[512];
        bool got = false;
        while (line.size() < IPC_MAX_LINE) {
            int n = (int)recv(c, chunk, sizeof(chunk), 0);
            if (n <= 0)
                break;
            line.append(chunk, (size_t)n);
            if (line.find('\n') != std::string::npos) {
                got = true;
                break;
            }
        }
        std::string reply;
        if (got) {
            size_t nl = line.find('\n');
            line.erase(nl == std::string::npos ? line.size() : nl);
            IpcRequest req;
            if (ipc_parse_request(line.c_str(), req) && req.cmd == "break_request") {
                ipc_break_flag = 1;
                reply = "{\"id\":" + std::to_string(req.id) +
                        ",\"ok\":true,\"queued\":true}\n";
            }
            else {
                reply = "{\"id\":0,\"ok\":false,\"error\":\"break channel only "
                        "accepts break_request\"}\n";
            }
        }
        else {
            reply = "{\"id\":0,\"ok\":false,\"error\":\"break channel timeout\"}\n";
        }
        (void)send(c, reply.data(), (int)reply.size(), 0);
        ipc_close_sock(c);
    }
    return 0;
}

int DEBUG_IPC_BreakRequested(void) {
    if (ipc_break_flag) {
        ipc_break_flag = 0;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Formatting helpers                                                   */
/* ------------------------------------------------------------------ */

static std::string ipc_hex16(unsigned v) {
    char b[16];
    snprintf(b, sizeof(b), "%04X", (unsigned)(v & 0xFFFFu));
    return std::string(b);
}

static std::string ipc_hex32(unsigned long long v) {
    char b[16];
    snprintf(b, sizeof(b), "%08llX", v & 0xFFFFFFFFull);
    return std::string(b);
}

/* Values emitted are identifiers/hex only; this keeps any stray quote
 * or backslash from breaking the line format. */
static std::string ipc_escape(const char* s) {
    std::string r;
    for (; s && *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            r += '\\';
            r += (char)c;
        }
        else if (c < 0x20 || c >= 0x7f)
            r += '?';
        else
            r += (char)c;
    }
    return r;
}

static std::string ipc_state_json(void) {
    char b[256];
    snprintf(b, sizeof(b),
             "\"state\":\"stopped\",\"reason\":\"%s\",\"core\":\"%s\","
             "\"cs\":\"%s\",\"eip\":\"%s\"",
             ipc_escape(ipc_stop_reason).c_str(),
             ipc_escape(DEBUG_IPC_CoreName()).c_str(),
             ipc_hex16(SegValue(cs)).c_str(),
             ipc_hex32(reg_eip).c_str());
    return std::string(b);
}

/* ------------------------------------------------------------------ */
/* Breakpoint id map (IPC-owned; list indices are unstable)             */
/* ------------------------------------------------------------------ */

struct IpcBpEntry {
    void* handle;
};
static std::map<long long, IpcBpEntry> ipc_bps;
static long long ipc_next_bp_id = 1;

/* ------------------------------------------------------------------ */
/* Command execution (guest stopped; main thread only)                 */
/* ------------------------------------------------------------------ */

/* debug.cpp (global; state-changing commands reuse the verified
 * interactive command path, including the RUN guards). */
bool ParseCommand(char* str);

static int ipc_cmd_continue(const IpcRequest& req) {
    char run[] = "RUN";
    if (!ParseCommand(run)) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"RUN rejected\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    char b[96];
    snprintf(b, sizeof(b),
             "{\"id\":%lld,\"ok\":true,\"state\":\"running\"}\n", req.id);
    ipc_send_line(b);
    return -1; /* DEBUG_Loop must return; loop switched to normal */
}

static int ipc_cmd_quit(const IpcRequest& req) {
    char b[96];
    snprintf(b, sizeof(b),
             "{\"id\":%lld,\"ok\":true,\"quitting\":true}\n", req.id);
    ipc_send_line(b);
    ipc_flush();
    char quit[] = "QUIT";
    ParseCommand(quit);
    return -1;
}

static int ipc_cmd_step(const IpcRequest& req) {
    if (!DEBUG_IPC_DoStep()) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"step failed\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    /* The step path does not re-enter DEBUG_Enable_Handler, so the stop is
     * announced by this command's response itself. */
    DEBUG_IPC_SetStopReason("step");
    std::string line = "{\"id\":" + std::to_string(req.id) +
                       ",\"ok\":true,\"event\":\"stopped\"," +
                       ipc_state_json() + "}\n";
    ipc_send_line(line);
    return 0;
}

static int ipc_cmd_bp_set(const IpcRequest& req) {
    unsigned long long seg = 0, off = 0;
    bool have = false;
    auto iseg = req.args.find("seg");
    auto ioff = req.args.find("off");
    if (iseg != req.args.end() && ioff != req.args.end())
        have = ipc_hex(iseg->second, &seg) && ipc_hex(ioff->second, &off);
    else {
        auto iaddr = req.args.find("addr");
        if (iaddr != req.args.end()) {
            size_t colon = iaddr->second.find(':');
            if (colon != std::string::npos)
                have = ipc_hex(iaddr->second.substr(0, colon), &seg) &&
                       ipc_hex(iaddr->second.substr(colon + 1), &off);
            else {
                /* bare linear address: real-mode seg:off split */
                unsigned long long lin;
                if (ipc_hex(iaddr->second, &lin) && lin <= 0xFFFFFul) {
                    seg = lin >> 4;
                    off = lin & 0xF;
                    have = true;
                }
            }
        }
    }
    if (!have || seg > 0xFFFFull || off > 0xFFFFull) {
        char b[128];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"bp_set wants "
                 "seg+off or addr seg:off\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    void* h = DEBUG_IPC_BPAddCode((uint16_t)seg, (uint32_t)off);
    if (!h) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"bp_add failed\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    long long id = ipc_next_bp_id++;
    ipc_bps[id] = IpcBpEntry{h};
    std::string line = "{\"id\":" + std::to_string(req.id) +
                       ",\"ok\":true,\"bp\":" + std::to_string(id) +
                       ",\"seg\":\"" + ipc_hex16((unsigned)seg) +
                       "\",\"off\":\"" + ipc_hex32(off) + "\"}\n";
    ipc_send_line(line);
    return 0;
}

static int ipc_cmd_bpint(const IpcRequest& req) {
    const std::string* pint = ipc_arg(req, "int");
    unsigned long long num;
    if (!pint || !ipc_hex(*pint, &num) || num > 0xFFull) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"bpint wants int\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    unsigned long long v;
    int ah = -1, al = -1;
    auto iah = req.args.find("ah");
    auto ial = req.args.find("al");
    if (iah != req.args.end() && ipc_hex(iah->second, &v) && v <= 0xFFull)
        ah = (int)v;
    if (ial != req.args.end() && ipc_hex(ial->second, &v) && v <= 0xFFull)
        al = (int)v;
    void* h = DEBUG_IPC_BPAddInt((uint8_t)num, ah, al);
    if (!h) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"bp_add failed\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    long long id = ipc_next_bp_id++;
    ipc_bps[id] = IpcBpEntry{h};
    std::string line = "{\"id\":" + std::to_string(req.id) +
                       ",\"ok\":true,\"bp\":" + std::to_string(id) + "}\n";
    ipc_send_line(line);
    return 0;
}

static int ipc_cmd_bp_clear(const IpcRequest& req) {
    const std::string* pwhich = ipc_arg(req, "bp");
    if (pwhich == nullptr) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"bp_clear wants bp "
                 "id or all\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    if (*pwhich == "all") {
        DEBUG_IPC_BPDeleteAll();
        ipc_bps.clear();
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":true,\"cleared\":\"all\"}\n", req.id);
        ipc_send_line(b);
        return 0;
    }
    unsigned long long id;
    if (!ipc_hex(*pwhich, &id)) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"bp_clear wants bp "
                 "id or all\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    auto it = ipc_bps.find((long long)id);
    bool found = (it != ipc_bps.end());
    bool deleted = false;
    if (found) {
        deleted = DEBUG_IPC_BPDelete(it->second.handle);
        ipc_bps.erase(it);
    }
    char b[96];
    snprintf(b, sizeof(b), "{\"id\":%lld,\"ok\":%s}\n", req.id,
             (found && deleted) ? "true" : "false");
    ipc_send_line(b);
    return 0;
}

static int ipc_cmd_bplist(const IpcRequest& req) {
    std::string line = "{\"id\":" + std::to_string(req.id) +
                       ",\"ok\":true,\"bps\":[";
    int index = 0;
    bool first = true;
    for (;;) {
        void* handle = nullptr;
        int kind = 0;
        uint16_t seg = 0;
        uint32_t off = 0;
        int int_nr = 0, ah = 0, al = 0;
        if (!DEBUG_IPC_BPGet(index, &handle, &kind, &seg, &off, &int_nr,
                             &ah, &al))
            break;
        long long id = 0;
        for (auto& kv : ipc_bps)
            if (kv.second.handle == handle) {
                id = kv.first;
                break;
            }
        if (!first) line += ",";
        first = false;
        line += "{";
        if (id != 0)
            line += "\"id\":" + std::to_string(id) + ",";
        else
            line += "\"source\":\"manual\",";
        if (kind == 1)
            line += "\"kind\":\"int\",\"int\":\"" + ipc_hex16((unsigned)int_nr) +
                    "\",\"ah\":" + (ah < 0 ? std::string("\"*\"") : "\"" + ipc_hex16((unsigned)ah) + "\"") +
                    ",\"al\":" + (al < 0 ? std::string("\"*\"") : "\"" + ipc_hex16((unsigned)al) + "\"");
        else if (kind == 0)
            line += "\"kind\":\"code\",\"seg\":\"" + ipc_hex16(seg) +
                    "\",\"off\":\"" + ipc_hex32(off) + "\"";
        else
            line += "\"kind\":\"other\",\"seg\":\"" + ipc_hex16(seg) +
                    "\",\"off\":\"" + ipc_hex32(off) + "\"";
        line += "}";
        index++;
    }
    line += "]}\n";
    ipc_send_line(line);
    return 0;
}

static int ipc_cmd_regs(const IpcRequest& req) {
    char b[512];
    snprintf(b, sizeof(b),
             "{\"id\":%lld,\"ok\":true,"
             "\"eax\":\"%08X\",\"ebx\":\"%08X\",\"ecx\":\"%08X\","
             "\"edx\":\"%08X\",\"esi\":\"%08X\",\"edi\":\"%08X\","
             "\"ebp\":\"%08X\",\"esp\":\"%08X\",\"eip\":\"%08X\","
             "\"cs\":\"%04X\",\"ds\":\"%04X\",\"es\":\"%04X\","
             "\"fs\":\"%04X\",\"gs\":\"%04X\",\"ss\":\"%04X\","
             "\"flags\":\"%08X\",\"cpl\":%u}\n",
             req.id, (unsigned)reg_eax, (unsigned)reg_ebx,
             (unsigned)reg_ecx, (unsigned)reg_edx, (unsigned)reg_esi,
             (unsigned)reg_edi, (unsigned)reg_ebp, (unsigned)reg_esp,
             (unsigned)reg_eip, (unsigned)SegValue(cs),
             (unsigned)SegValue(ds), (unsigned)SegValue(es),
             (unsigned)SegValue(fs), (unsigned)SegValue(gs),
             (unsigned)SegValue(ss), (unsigned)(uint32_t)reg_flags,
             (unsigned)cpu.cpl);
    ipc_send_line(b);
    return 0;
}

static int ipc_cmd_mem_write(const IpcRequest& req) {
    const std::string* pseg = ipc_arg(req, "seg");
    const std::string* poff = ipc_arg(req, "off");
    const std::string* phex = ipc_arg(req, "hex");
    unsigned long long seg = 0, off = 0;
    if (!pseg || !poff || !phex ||
        !ipc_hex(*pseg, &seg) || !ipc_hex(*poff, &off) ||
        seg > 0xFFFFull || off > 0xFFFFull) {
        ipc_send_line("{\"id\":0,\"ok\":false,\"error\":\"mem_write wants "
                      "seg,off,hex\"}\n");
        return 0;
    }
    const std::string& hex = *phex;
    if (hex.empty() || hex.size() % 2 ||
        hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos ||
        hex.size() / 2 > 128) {
        ipc_send_line("{\"id\":0,\"ok\":false,\"error\":\"mem_write hex must "
                      "be 1..128 bytes\"}\n");
        return 0;
    }
    /* Named write path: reuse the debugger's own SM command semantics
     * (space-separated byte values after seg:off). */
    std::string spaced;
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        if (!spaced.empty())
            spaced += ' ';
        spaced += hex.substr(i, 2);
    }
    std::string command = "SM " + ipc_hex16((unsigned)seg) + ":" +
                          ipc_hex32(off) + " " + spaced;
    char buffer[512];
    snprintf(buffer, sizeof(buffer), "%s", command.c_str());
    if (!ParseCommand(buffer)) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"SM rejected\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    char b[96];
    snprintf(b, sizeof(b), "{\"id\":%lld,\"ok\":true,\"written\":%u}\n",
             req.id, (unsigned)(hex.size() / 2));
    ipc_send_line(b);
    return 0;
}

static int ipc_cmd_reg_write(const IpcRequest& req) {
    const std::string* preg = ipc_arg(req, "reg");
    const std::string* pval = ipc_arg(req, "value");
    unsigned long long value = 0;
    if (!preg || !pval || preg->empty() || preg->size() > 8 ||
        preg->find_first_not_of("abcdefghijklmnopqrstuvwxyz"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "0123456789") != std::string::npos ||
        !ipc_hex(*pval, &value) || value > 0xFFFFFFFFull) {
        ipc_send_line("{\"id\":0,\"ok\":false,\"error\":\"reg_write wants "
                      "reg,value\"}\n");
        return 0;
    }
    /* Named write path: SR label value (writes the register's low word for
     * 16-bit labels, matching the debugger console semantics). */
    std::string upper;
    for (char c : *preg)
        upper += (char)toupper((unsigned char)c);
    std::string command = "SR " + upper + " " + ipc_hex32(value);
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s", command.c_str());
    if (!ParseCommand(buffer)) {
        char b[96];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"SR rejected\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    char b[96];
    snprintf(b, sizeof(b),
             "{\"id\":%lld,\"ok\":true,\"reg\":\"%s\",\"value\":\"%s\"}\n",
             req.id, ipc_escape(upper.c_str()).c_str(), ipc_hex32(value).c_str());
    ipc_send_line(b);
    return 0;
}

/* ---- v1.2 savestate / loadstate ----
 *
 * Structured state-slot control so controllers do not have to synthesize
 * the F12+S/F12+L mapper hotkeys (which only exist as host SDL events).
 * Serviced from the debugger stop branch, so the serialized snapshot is
 * race-free. These call the SaveState core directly instead of the
 * SaveGameState()/LoadGameState() hotkey handlers: the handlers report
 * failures through systemmessagebox(), which would block this loop when
 * no operator is watching. Divergences from the hotkey path: the TTF
 * font-size reset the load handler performs is skipped, and save-to-file
 * mode (use_save_file) is not honored -- slot-based saving only. */

static void ipc_state_send_slot_error(long long id, const char* cmd) {
    char b[128];
    snprintf(b, sizeof(b),
             "{\"id\":%lld,\"ok\":false,\"error\":\"%s wants slot "
             "0..9 (decimal, optional; defaults to the active slot)\"}\n",
             id, cmd);
    ipc_send_line(b);
}

static void ipc_state_send_ok(long long id, const char* cmd, size_t slot,
                              size_t previous_slot) {
    std::string name = SaveState::instance().getName(slot);
    std::string r = "{\"id\":" + std::to_string(id) + ",\"ok\":true,\"cmd\":\"" +
                    cmd + "\",\"slot\":" + std::to_string(slot) +
                    ",\"slot_label\":" + std::to_string(slot + 1) +
                    ",\"slot_file\":\"" + std::to_string(slot + 1) +
                    ".sav\",\"previous_slot\":" +
                    std::to_string(previous_slot) + ",\"name\":\"" +
                    ipc_escape(name.c_str()) + "\"}\n";
    ipc_send_line(r);
}

static void ipc_state_send_fail(long long id, const char* cmd, size_t slot,
                                const char* error) {
    std::string r = "{\"id\":" + std::to_string(id) + ",\"ok\":false,\"cmd\":\"" +
                    cmd + "\",\"slot\":" + std::to_string(slot) +
                    ",\"error\":\"" + ipc_escape(error) + "\"}\n";
    ipc_send_line(r);
}

/* Shared argument handling: optional decimal "slot" 0..9, defaulting to
 * the active slot. Returns false (response already sent) on bad input. */
static bool ipc_state_slot_arg(const IpcRequest& req, const char* cmd,
                               size_t* slot) {
    size_t active = GetGameState_Run();
    *slot = active;
    const std::string* pslot = ipc_arg(req, "slot");
    if (pslot == nullptr)
        return true;
    unsigned long long v = 0;
    if (!ipc_uint(*pslot, &v) || v >= SaveState::SLOT_COUNT) {
        ipc_state_send_slot_error(req.id, cmd);
        return false;
    }
    *slot = (size_t)v;
    return true;
}

static int ipc_cmd_savestate(const IpcRequest& req) {
    size_t slot = 0;
    if (!ipc_state_slot_arg(req, "savestate", &slot))
        return 0;
    size_t previous_slot = GetGameState_Run();
    /* SaveState::save() prompts for a remark through a tinyfd modal
     * unless suppressed; a modal here would deadlock the IPC loop (and
     * the whole emulator) with no operator present. Force the
     * non-interactive path for the duration of the call. */
    bool prev_noremark = noremark_save_state;
    noremark_save_state = true;
    try {
        SaveState::instance().save(slot);
        noremark_save_state = prev_noremark;
    } catch (const SaveState::Error& err) {
        noremark_save_state = prev_noremark;
        ipc_state_send_fail(req.id, "savestate", slot, err.c_str());
        return 0;
    }
    /* Explicit-slot saves must not move the menu's active slot (same
     * discipline as the vga_draw autosave path). */
    if (slot != previous_slot)
        SetGameState_Run((int)previous_slot);
    ipc_state_send_ok(req.id, "savestate", slot, previous_slot);
    return 0;
}

static int ipc_cmd_loadstate(const IpcRequest& req) {
    size_t slot = 0;
    if (!ipc_state_slot_arg(req, "loadstate", &slot))
        return 0;
    size_t previous_slot = GetGameState_Run();
    if (SaveState::instance().isEmpty(slot)) {
        ipc_state_send_fail(req.id, "loadstate", slot, "slot is empty");
        return 0;
    }
    try {
        SaveState::instance().load(slot);
    } catch (const SaveState::Error& err) {
        ipc_state_send_fail(req.id, "loadstate", slot, err.c_str());
        return 0;
    }
    if (slot != previous_slot)
        SetGameState_Run((int)previous_slot);
    ipc_state_send_ok(req.id, "loadstate", slot, previous_slot);
    return 0;
}

static int ipc_cmd_mem_read(const IpcRequest& req) {
    const std::string* pseg = ipc_arg(req, "seg");
    const std::string* poff = ipc_arg(req, "off");
    const std::string* plen = ipc_arg(req, "len");
    unsigned long long seg, off, len;
    if (!pseg || !poff || !plen ||
        !ipc_hex(*pseg, &seg) || !ipc_hex(*poff, &off) ||
        !ipc_uint(*plen, &len) || seg > 0xFFFFull ||
        off > 0xFFFFull || len == 0 || len > IPC_MEMREAD_MAX) {
        char b[128];
        snprintf(b, sizeof(b),
                 "{\"id\":%lld,\"ok\":false,\"error\":\"mem_read wants "
                 "seg,off,len (len 1..65536)\"}\n",
                 req.id);
        ipc_send_line(b);
        return 0;
    }
    std::string hex;
    hex.reserve((size_t)len * 2 + 64);
    uint8_t val = 0;
    for (unsigned long long i = 0; i < len; i++) {
        /* Same canonical access as MEMDUMPBIN: per-byte checked read;
         * GetAddress() applies segment wrap-around. */
        if (mem_readb_checked((PhysPt)GetAddress((uint16_t)seg,
                                                 (uint32_t)(off + i)),
                              &val)) {
            char b[128];
            snprintf(b, sizeof(b),
                     "{\"id\":%lld,\"ok\":false,\"error\":\"unreadable at "
                     "offset %llu\"}\n",
                     req.id, i);
            ipc_send_line(b);
            return 0;
        }
        char hb[4];
        snprintf(hb, sizeof(hb), "%02X", val);
        hex += hb;
    }
    std::string line = "{\"id\":" + std::to_string(req.id) +
                       ",\"ok\":true,\"seg\":\"" + ipc_hex16((unsigned)seg) +
                       "\",\"off\":\"" + ipc_hex32(off) + "\",\"len\":" +
                       std::to_string(len) + ",\"hex\":\"" + hex + "\"}\n";
    ipc_send_line(line);
    return 0;
}

/* Named emulator input, separate from guest memory/register writes. A caller
 * must bind every mutation to the current stopped CPU. It may release buttons
 * during cleanup at an unknown game screen, but must reacquire UI ownership
 * before pressing. These commands never resume execution by themselves. */
static bool ipc_mouse_initialized = false;
static uint8_t ipc_mouse_buttons = 0;

static int ipc_cmd_mouse_input(const IpcRequest& req) {
    unsigned long long expected_cs, ip, expected_ss, bp, sp, x, y, buttons;
    const char* fields[] = {"cs", "ip", "ss", "bp", "sp", "x", "y", "buttons"};
    unsigned long long* values[] = {&expected_cs, &ip, &expected_ss, &bp, &sp, &x, &y, &buttons};
    for (unsigned i = 0; i < 8; ++i) {
        const std::string* value = ipc_arg(req, fields[i]);
        if (!value || !ipc_hex(*value, values[i])) {
            ipc_send_line("{\"id\":" + std::to_string(req.id) +
                          ",\"ok\":false,\"error\":\"mouse_input requires hexadecimal CPU and input fields\"}\n");
            return 0;
        }
    }
    if (expected_cs > 0xFFFF || ip > 0xFFFF || expected_ss > 0xFFFF || bp > 0xFFFF ||
        sp > 0xFFFF || x >= 640 || y >= 480 || buttons > 7 || cpu.cpl != 0 ||
        expected_cs != SegValue(cs) || ip != reg_eip || expected_ss != SegValue(ss) ||
        bp != reg_ebp || sp != reg_esp) {
        ipc_send_line("{\"id\":" + std::to_string(req.id) +
                      ",\"ok\":false,\"error\":\"mouse_input bounds or stopped CPU guard mismatch\"}\n");
        return 0;
    }
    if (!ipc_mouse_initialized && buttons != 0) {
        ipc_send_line("{\"id\":" + std::to_string(req.id) +
                      ",\"ok\":false,\"error\":\"mouse_input must establish released ownership first\"}\n");
        return 0;
    }
    Mouse_SetClientCursorPos((int16_t)x, (int16_t)y);
    for (uint8_t i = 0; i < 3; ++i) {
        const uint8_t mask = (uint8_t)(1u << i);
        if (!ipc_mouse_initialized || ((ipc_mouse_buttons & mask) && !(buttons & mask)))
            Mouse_ButtonReleased(i);
        if ((buttons & mask) && !(ipc_mouse_buttons & mask))
            Mouse_ButtonPressed(i);
    }
    ipc_mouse_initialized = true;
    ipc_mouse_buttons = (uint8_t)buttons;
    ipc_send_line("{\"id\":" + std::to_string(req.id) +
                  ",\"ok\":true,\"accepted\":true,\"state\":\"stopped\",\"buttons\":" +
                  std::to_string(buttons) + ",\"delivery\":\"emulator_mouse_api\"}\n");
    return 0;
}

static int ipc_handle_line(const std::string& line) {
    if (line.empty())
        return 0;
    IpcRequest req;
    if (!ipc_parse_request(line.c_str(), req)) {
        ipc_send_line("{\"id\":0,\"ok\":false,\"error\":\"bad request\"}\n");
        return 0;
    }
    if (req.cmd == "hello") {
        std::string r = "{\"id\":" + std::to_string(req.id) +
                        ",\"ok\":true,\"proto\":1,"
                        "\"server\":\"dosbox-x-debugger-ipc\",\"features\":[\"stopped_mouse_v1\"]," +
                        ipc_state_json() + "}\n";
        ipc_send_line(r);
        return 0;
    }
    if (req.cmd == "state") {
        std::string r = "{\"id\":" + std::to_string(req.id) + ",\"ok\":true," +
                        ipc_state_json() + "}\n";
        ipc_send_line(r);
        return 0;
    }
    if (req.cmd == "bp_set")   return ipc_cmd_bp_set(req);
    if (req.cmd == "bpint")    return ipc_cmd_bpint(req);
    if (req.cmd == "bp_clear") return ipc_cmd_bp_clear(req);
    if (req.cmd == "bplist")   return ipc_cmd_bplist(req);
    if (req.cmd == "regs")     return ipc_cmd_regs(req);
    if (req.cmd == "mem_read") return ipc_cmd_mem_read(req);
    if (req.cmd == "mouse_input") return ipc_cmd_mouse_input(req);
    if (req.cmd == "mem_write") return ipc_cmd_mem_write(req);
    if (req.cmd == "reg_write") return ipc_cmd_reg_write(req);
    if (req.cmd == "savestate") return ipc_cmd_savestate(req);
    if (req.cmd == "loadstate") return ipc_cmd_loadstate(req);
    if (req.cmd == "continue") return ipc_cmd_continue(req);
    if (req.cmd == "step")     return ipc_cmd_step(req);
    if (req.cmd == "quit")     return ipc_cmd_quit(req);

    char b[128];
    snprintf(b, sizeof(b),
             "{\"id\":%lld,\"ok\":false,\"error\":\"unknown command "
             "'%s'\"}\n",
             req.id, ipc_escape(req.cmd.c_str()).c_str());
    ipc_send_line(b);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public service points                                                */
/* ------------------------------------------------------------------ */

int DEBUG_IPC_Poll(void) {
    if (listen_socket == IPC_BAD_SOCKET)
        return 0;
    ipc_try_accept();
    if (client_socket == IPC_BAD_SOCKET)
        return 0;
    ipc_recv_requests();
    int status = 0;
    for (;;) {
        if (client_socket == IPC_BAD_SOCKET)
            break;
        size_t nl = inbuf.find('\n');
        if (nl == std::string::npos)
            break;
        std::string line = inbuf.substr(0, nl);
        inbuf.erase(0, nl + 1);
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        status = ipc_handle_line(line);
        if (status != 0)
            break; /* continue/quit: leave remaining lines buffered */
    }
    ipc_flush();
    return status;
}

void DEBUG_IPC_NotifyStopped(void) {
    if (client_socket == IPC_BAD_SOCKET)
        return;
    std::string line = "{\"id\":0,\"event\":\"stopped\"," +
                       ipc_state_json() + "}\n";
    ipc_send_line(line);
}

void DEBUG_IPC_NotifyRunning(void) {
    if (client_socket == IPC_BAD_SOCKET)
        return;
    ipc_send_line("{\"id\":0,\"event\":\"running\"}\n");
}

void DEBUG_IPC_SetStopReason(const char* reason) {
    if (reason && *reason)
        ipc_stop_reason = reason;
}

#endif /* C_DEBUG */
