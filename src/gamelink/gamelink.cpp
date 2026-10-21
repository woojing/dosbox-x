
// Game Link

//------------------------------------------------------------------------------
// Dependencies
//------------------------------------------------------------------------------

#include "config.h"

#if C_GAMELINK

// define this to debug memory offset detection
// #define DEBUG_SNOOP

// Local Dependencies
#include "dosbox.h"
#include "gamelink.h"
#include "logging.h"
#include "sdlmain.h"
#include "cpu.h"
#include "cpu/lazyflags.h"
#include "timer.h"
#include "mouse.h"
#include <time.h>
#ifdef WIN32
#include "../resource.h"
#endif

// External Dependencies
#ifdef WIN32
#include <Windows.h>
#else // WIN32
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <semaphore.h>
#endif // WIN32

// SDL Dependencies
#include "SDL_syswm.h"
#include "SDL.h"

extern bool is_paused;
#if C_DEBUG
extern bool IsDebuggerActive(void);
#endif
extern uint32_t RunningProgramLoadAddress;

//==============================================================================

//------------------------------------------------------------------------------
// Local Definitions
//------------------------------------------------------------------------------

#define SYSTEM_NAME		"DOSBox"

#define PROTOCOL_VER		5

#ifdef WIN32
#define GAMELINK_MUTEX_NAME		"DWD_GAMELINK_MUTEX_R4"
#else // WIN32
#define GAMELINK_MUTEX_NAME		"/DWD_GAMELINK_MUTEX_R4"
#endif // WIN32

#ifdef MACOSX
#define GAMELINK_MMAP_NAME		"/DWD_GAMELINK_MMAP_R4"
#else // MACOSX
#define GAMELINK_MMAP_NAME		"DWD_GAMELINK_MMAP_R4"
#endif // MACOSX


//------------------------------------------------------------------------------
// Local Data
//------------------------------------------------------------------------------

#ifdef WIN32

static HANDLE g_mutex_handle;
static HANDLE g_mmap_handle;

#else // WIN32

static sem_t* g_mutex_handle;
static int g_mmap_handle; // fd!

#endif // WIN32

static bool g_trackonly_mode;

static uint32_t g_membase_size;

static GameLink::sSharedMemoryMap_R4* g_p_shared_memory;

#define MEMORY_MAP_CORE_SIZE sizeof( GameLink::sSharedMemoryMap_R4 )


//------------------------------------------------------------------------------
// Local Functions
//------------------------------------------------------------------------------

// Optional project-local running transport. Independent from protocol v5.
// All access uses the existing GameLink mutex. Only this emulator-thread tick
// copies CPU/RAM or injects input: shared MemBase itself is NOT a snapshot.
#ifndef WIN32
#define HERO_LIVE_NAME "/DWD_HERO_LIVE_V1"
static const uint32_t HERO_LIVE_MAGIC = 0x48525631;
#pragma pack(push, 1)
struct HeroLiveGuard {
    uint32_t offset, length;
    uint8_t expected[64];
};
struct HeroLiveMap {
    uint32_t magic, version, map_bytes, owner_pid;
    uint64_t generation, capture_request, capture_done;
    GameLink::sSharedMMapRegs_R1 regs;
    char program[260];
    uint64_t input_request, input_done, input_generation;
    uint32_t input_load_phys, input_ss, input_owner_bp;
    int32_t input_x, input_y;
    uint32_t input_buttons, guard_count, receipt_status, receipt_reason;
    GameLink::sSharedMMapRegs_R1 receipt_regs;
    HeroLiveGuard guards[128];
    uint8_t ram[0x100000];
};
#pragma pack(pop)
static_assert(sizeof(HeroLiveMap) == 1058280, "hero live sidecar ABI drift");
static HeroLiveMap* g_hero_live = NULL;
static bool g_hero_mouse_initialized = false;
static uint8_t g_hero_mouse_buttons = 0;
static uint64_t g_hero_wait_id = 0;
static uint32_t g_hero_wait_started = 0;

static void gamelink_live_init()
{
    if (sdl.gamelink.snoop || g_membase_size < 0x100000) return;
    int fd = shm_open(HERO_LIVE_NAME, O_CREAT | O_RDWR, 0600);
    if (fd < 0) { LOG_MSG("HERO_LIVE: shm_open failed: %d", errno); return; }
    // There is one GameLink master. Existing mappings survive a crash; a new
    // generation invalidates all prior captures, queued requests and receipts.
    fchmod(fd, 0600);
    if (ftruncate(fd, sizeof(HeroLiveMap)) != 0) { close(fd); return; }
    void* ptr = mmap(NULL, sizeof(HeroLiveMap), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (ptr == MAP_FAILED) return;
    g_hero_live = static_cast<HeroLiveMap*>(ptr);
    memset(g_hero_live, 0, sizeof(*g_hero_live));
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    g_hero_live->version = 1;
    g_hero_live->map_bytes = sizeof(HeroLiveMap);
    g_hero_live->owner_pid = (uint32_t)getpid();
    g_hero_live->generation = ((uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec) ^ ((uint64_t)getpid() << 32);
    g_hero_mouse_initialized = false;
    g_hero_mouse_buttons = 0;
    g_hero_wait_id = 0;
    g_hero_live->magic = HERO_LIVE_MAGIC;
}

static void gamelink_live_term()
{
    if (!g_hero_live) return;
    g_hero_live->magic = 0;
    munmap(g_hero_live, sizeof(HeroLiveMap));
    g_hero_live = NULL;
    shm_unlink(HERO_LIVE_NAME);
}

// Bounded static UI-consumer poll contracts. A live owner frame can still
// exist during initialization or after a press, so ownership alone is not input
// authority. Only the actual current instruction/helper path below is admitted.
static bool hero_live_word(const uint8_t* ram, uint32_t ss, uint32_t off, uint32_t& value)
{
    const uint32_t address = ss * 16 + off;
    if (off > 0xfffe || address + 2 > 0x100000) return false;
    value = ram[address] | ((uint32_t)ram[address + 1] << 8);
    return true;
}

static bool hero_live_frame(const uint8_t* ram, uint32_t ss, uint32_t bp,
                            uint32_t& parent, uint32_t& ret, uint32_t& retseg,
                            uint32_t& entry, uint32_t& segment)
{
    if (bp < 2 || bp > 0xfff0 || !hero_live_word(ram, ss, bp, parent) ||
        !hero_live_word(ram, ss, bp + 2, ret) || !hero_live_word(ram, ss, bp + 4, retseg) ||
        parent <= bp || parent > 0xfff0 || ret < 5) return false;
    const uint32_t address = retseg * 16 + ret - 5;
    if (address + 5 > 0x100000 || ram[address] != 0x9a) return false;
    entry = ram[address + 1] | ((uint32_t)ram[address + 2] << 8);
    segment = ram[address + 3] | ((uint32_t)ram[address + 4] << 8);
    return true;
}

static bool hero_live_poll_ready(const uint8_t* ram, const HeroLiveMap& h)
{
    if ((RunningProgramLoadAddress & 15) || cpu.pmode || cpu.cpl) return false;
    const uint32_t delta = RunningProgramLoadAddress >> 4;
    const uint32_t stack_segment = SegValue(ss), code_segment = SegValue(cs);
    const uint32_t ss = stack_segment, pc = reg_eip, cs = code_segment;
    uint32_t bp = reg_ebp & 0xffff, sp = reg_esp & 0xffff;
    if (ss != h.input_ss || ss != delta + 0x313a || SegValue(ds) != ss || sp > bp) return false;
    uint32_t parent, ret, retseg, owner, ownerseg;
    if (!hero_live_frame(ram, ss, h.input_owner_bp, parent, ret, retseg, owner, ownerseg)) return false;
    if (!((ownerseg == delta + 0x1cb6 && (owner == 0x44de || owner == 0x5786)) ||
          (ownerseg == delta + 0x0cf5 && (owner == 0x3310 || owner == 0x2c92 || owner == 0x3c5e)))) return false;
    if (bp == h.input_owner_bp) {
        if (cs != ownerseg) return false;
        if (owner == 0x44de) return (pc >= 0x45ba && pc < 0x46f2) || (pc >= 0x4723 && pc < 0x4734);
        if (owner == 0x5786) return (pc >= 0x5860 && pc < 0x5877) || (pc >= 0x5889 && pc < 0x58d2);
        return false; // Lists/notices need an actual initialized polling helper.
    }
    uint32_t entry = 0, segment = cs;
    if (cs == delta && pc >= 0xc505 && pc < 0xc57c) entry = 0xc502;
    if (cs == delta + 0x0cf5) {
        if (pc >= 0x105b && pc < 0x1085) entry = 0x1054;
        else if (pc >= 0x10b5 && pc < 0x10d1) entry = 0x10b2;
        else if (pc >= 0x10d9 && pc < 0x10f5) entry = 0x10d6;
        else if (pc >= 0x127d && pc < 0x1293) entry = 0x127a;
        else if (pc >= 0x1d34 && pc < 0x1d6c) entry = 0x1d2e;
        else if (pc >= 0x1f8a && pc < 0x1fab) entry = 0x1f84;
    }
    if (!entry) return false;
    uint32_t button = 0, array = 0;
    for (unsigned depth = 0; depth < 12; ++depth) {
        uint32_t a = 0, b = 0, c = 0, actual_entry, actual_segment;
        if (!hero_live_frame(ram, ss, bp, parent, ret, retseg, actual_entry, actual_segment) ||
            entry != actual_entry || segment != actual_segment) return false;
        if (entry == 0xc502) {
            if (!hero_live_word(ram, ss, bp + 6, a) || !hero_live_word(ram, ss, bp + 8, b) ||
                !hero_live_word(ram, ss, bp + 10, c) || a != 0x33 || b != 0x64fe || c != 0x64fe ||
                retseg != delta + 0x0cf5 || ret != 0x1290) return false;
            entry = 0x127a;
        } else if (entry == 0x127a) {
            if (!hero_live_word(ram, ss, bp + 6, a) || !hero_live_word(ram, ss, bp + 8, b) ||
                a != 0x64e2 || b != 3 || retseg != delta + 0x0cf5) return false;
            if (ret == 0x1069) entry = 0x1054;
            else if (ret == 0x10c5) entry = 0x10b2;
            else if (ret == 0x10e9) entry = 0x10d6;
            else return false;
        } else if (entry == 0x1054 || entry == 0x10b2 || entry == 0x10d6) {
            if (!hero_live_word(ram, ss, bp + 6, a) || a != 0x64e2) return false;
            if (retseg == delta + 0x0cf5 && ((entry == 0x1054 && ret == 0x1d3c) || (entry == 0x10b2 && ret == 0x1d5c))) entry = 0x1d2e;
            else if (retseg == delta + 0x1cb6 && entry == 0x10b2 && ret == 0x46f2) entry = 0x44de;
            else if (retseg == delta + 0x1cb6 && entry == 0x10d6 && ret == 0x4734) entry = 0x44de;
            else if (retseg == delta + 0x1cb6 && entry == 0x10b2 && (ret == 0x586b || ret == 0x5877)) entry = 0x5786;
            else if (retseg == delta + 0x1cb6 && entry == 0x10d6 && ret == 0x58d2) entry = 0x5786;
            else if (retseg == delta + 0x1cb6 && entry == 0x10b2 && ret == 0x5b73) entry = 0x5924;
            else return false;
        } else if (entry == 0x1d2e) {
            if (!hero_live_word(ram, ss, bp + 6, button) || retseg != delta + 0x0cf5) return false;
            if (ret == 0x1fab) entry = 0x1f84;
            else if (ret == 0x3f77 || ret == 0x3f87 || ret == 0x3f9e) {
                entry = 0x3c5e;
                const uint32_t relative = ret == 0x3f77 ? 0x38 : ret == 0x3f87 ? 0x46 : 0x2a;
                if (button != parent - relative) return false;
            } else return false;
        } else if (entry == 0x1f84) {
            if (!hero_live_word(ram, ss, bp + 6, array) || bp < 1 || ram[ss * 16 + bp - 1] != 0xff || retseg != delta + 0x0cf5) return false;
            if (ret == 0x369c) entry = 0x3310;
            else if (ret == 0x3023) entry = 0x2c92;
            else return false;
            if (array != parent - 0xd8) return false;
            if (button) {
                const uint32_t count = ram[ss * 16 + array];
                if (!count || count > 12 || button < array + 4 || (button - array - 4) % 14 || (button - array - 4) / 14 >= count) return false;
            }
        } else if (entry == 0x5924) {
            if (!hero_live_word(ram, ss, bp + 6, a) || a != 0xe1bc || retseg != delta + 0x1cb6) return false;
            if (ret == 0x45d1) entry = 0x44de;
            else if (ret == 0x5895) entry = 0x5786;
            else return false;
        } else return false;
        segment = retseg;
        bp = parent;
        if (bp == h.input_owner_bp) return entry == owner && segment == ownerseg;
        if (bp > h.input_owner_bp) return false;
    }
    return false;
}

// A valid queued intent may arrive between polls. Keep that SAME request
// pending for at most one wall-clock second; every tick rechecks owner and
// decision bytes before admission. This never retransmits an accepted input.
static bool hero_live_defer_poll(uint64_t request, uint32_t reason)
{
    if (reason != 8) { g_hero_wait_id = 0; return false; }
    const uint32_t now = GetTicks();
    if (g_hero_wait_id != request) {
        g_hero_wait_id = request;
        g_hero_wait_started = now;
    }
    return (uint32_t)(now - g_hero_wait_started) < 1000;
}

// Called while holding GameLink's mutex, from the GFX_Events/Out emulator
// thread. Receipt status 1 = delivered to Mouse API, 2 = rejected; never an
// assertion that the game consumed input or completed an action.
static void gamelink_live_tick()
{
    if (!g_hero_live || !g_p_shared_memory || is_paused) return;
#if C_DEBUG
    // Out() also runs in debugger/pause display loops. These are not running
    // captures and must not service live input or relabel stopped CPU state.
    if (IsDebuggerActive()) return;
#endif
    HeroLiveMap& h = *g_hero_live;
    uint8_t* ram = ((uint8_t*)g_p_shared_memory) + MEMORY_MAP_CORE_SIZE;
    if (h.input_request && h.input_request != h.input_done) {
        uint32_t reason = 0;
        const bool release = h.input_buttons == 0 && h.input_x == -1 && h.input_y == -1;
        if (h.input_generation != h.generation) reason = 1;
        else if (!release && h.input_load_phys != RunningProgramLoadAddress) reason = 2;
        else if (h.input_buttons > 7 || h.guard_count > 128 ||
                 (!release && (h.input_x < 0 || h.input_x >= 640 || h.input_y < 0 || h.input_y >= 480 || !h.guard_count))) reason = 3;
        else if (!release && is_paused) reason = 5;
        else if (!release && h.input_buttons && !g_hero_mouse_initialized) reason = 6;
        if (!reason && !release) {
            // Stale stack bytes can survive a return. Require the nominated
            // owner in the CURRENT increasing BP chain, never an RAM scan.
            uint32_t bp = reg_ebp & 0xffff;
            bool active_owner = false;
            if (cpu.pmode || cpu.cpl || h.input_ss != SegValue(ss) || h.input_owner_bp < 2 || h.input_owner_bp > 0xfff0) reason = 7;
            else for (uint32_t depth = 0; depth < 32; ++depth) {
                if (bp == h.input_owner_bp) { active_owner = true; break; }
                uint32_t address = (uint32_t)SegValue(ss) * 16 + bp;
                if (bp < 2 || bp > 0xfff0 || address + 2 > 0x100000) break;
                uint32_t parent = ram[address] | ((uint32_t)ram[address + 1] << 8);
                if (parent <= bp || parent > 0xfff0) break;
                bp = parent;
            }
            if (!active_owner) reason = 7;
        }
        if (!reason && !release) for (uint32_t i = 0; i < h.guard_count; ++i) {
            const HeroLiveGuard& g = h.guards[i];
            if (!g.length || g.length > 64 || g.offset >= 0x100000 || g.length > 0x100000 - g.offset) { reason = 3; break; }
            if (memcmp(ram + g.offset, g.expected, g.length) != 0) { reason = 4; break; }
        }
        if (!reason && !release && !hero_live_poll_ready(ram, h)) reason = 8;
        const bool defer = hero_live_defer_poll(h.input_request, reason);
        if (!reason) {
            if (!release) {
                extern void Mouse_SetClientCursorPos(int16_t x, int16_t y);
                Mouse_SetClientCursorPos((int16_t)h.input_x, (int16_t)h.input_y);
            }
            const uint8_t buttons = (uint8_t)h.input_buttons;
            for (uint8_t i = 0; i < 3; ++i) {
                const uint8_t mask = 1 << i;
                if ((buttons & mask) && !(g_hero_mouse_buttons & mask)) Mouse_ButtonPressed(i);
                if (!(buttons & mask) && ((g_hero_mouse_buttons & mask) || !g_hero_mouse_initialized || release)) Mouse_ButtonReleased(i);
            }
            g_hero_mouse_initialized = true;
            g_hero_mouse_buttons = buttons;
        }
        if (!defer) {
            h.receipt_status = reason ? 2 : 1;
            h.receipt_reason = reason;
            h.receipt_regs = g_p_shared_memory->regs;
            h.input_done = h.input_request;
        }
    }
    if (h.capture_request != h.capture_done) {
        h.regs = g_p_shared_memory->regs;
        memcpy(h.program, g_p_shared_memory->program, sizeof(h.program));
        memcpy(h.ram, ram, sizeof(h.ram));
        h.capture_done = h.capture_request;
    }
}
#else
static void gamelink_live_init() {}
static void gamelink_live_term() {}
static void gamelink_live_tick() {}
#endif

// Register snapshot writer shared by GameLink::Out() and the heartbeat
// heartbeat below. Callers must already hold the shared mutex and must not be
// a snoop instance.
static void gamelink_write_regs_snapshot()
{
	FillFlags();
	GameLink::sSharedMMapRegs_R1& r = g_p_shared_memory->regs;
	r.eip = (uint32_t)reg_eip;
	r.esp = (uint32_t)reg_esp;
	r.ebp = (uint32_t)reg_ebp;
	r.esi = (uint32_t)reg_esi;
	r.edi = (uint32_t)reg_edi;
	r.eax = (uint32_t)reg_eax;
	r.ebx = (uint32_t)reg_ebx;
	r.ecx = (uint32_t)reg_ecx;
	r.edx = (uint32_t)reg_edx;
	r.eflags = (uint32_t)reg_flags;
	r.program_load_phys = RunningProgramLoadAddress;
	r.cs = SegValue( cs );
	r.ds = SegValue( ds );
	r.es = SegValue( es );
	r.ss = SegValue( ss );
	r.fs = SegValue( fs );
	r.gs = SegValue( gs );
	r.cpl = (uint8_t)cpu.cpl;
	r.pmode = cpu.pmode ? 1 : 0;
	++r.seq;
}

// Heartbeat: a mouse-wait loop may draw nothing, and savestate restoration
// replaces PIC's serialized timer-handler list. GFX_Events calls this on the
// emulator thread independently of rendering or that list, at ~60 Hz wall time.
static void gamelink_regs_tick()
{
	static uint32_t last_ms = 0;
	uint32_t now_ms = GetTicks();
	if ( now_ms - last_ms < 15 )
		return;
	last_ms = now_ms;

	if ( g_p_shared_memory == NULL || sdl.gamelink.snoop )
		return;

	// Take the same named mutex Out() uses; never block the emulator on a
	// slow client - skip this tick instead.
#ifdef WIN32
	DWORD wait = WaitForSingleObject( g_mutex_handle, 0 );
	if ( wait != WAIT_OBJECT_0 && wait != WAIT_ABANDONED )
		return;
#else
	int result = sem_trywait( g_mutex_handle );
	if ( result < 0 )
		return;
#endif

	gamelink_write_regs_snapshot();
	gamelink_live_tick();

#ifdef WIN32
	ReleaseMutex( g_mutex_handle );
#else
	sem_post( g_mutex_handle );
#endif
}

void GameLink::PollLive()
{
    // No timer/PIC registration: this must survive restoring old saved states
    // without adding an unserializable function pointer to future saves.
    gamelink_regs_tick();
}


static void shared_memory_init()
{
	if (sdl.gamelink.snoop) return;

	// Initialise

	g_p_shared_memory->version = PROTOCOL_VER;
	g_p_shared_memory->flags = 0;

	memset( g_p_shared_memory->system, 0, sizeof( g_p_shared_memory->system ) );
	strcpy( g_p_shared_memory->system, SYSTEM_NAME );
	memset( g_p_shared_memory->program, 0, sizeof( g_p_shared_memory->program ) );

	g_p_shared_memory->program_hash[ 0 ] = 0;
	g_p_shared_memory->program_hash[ 1 ] = 0;
	g_p_shared_memory->program_hash[ 2 ] = 0;
	g_p_shared_memory->program_hash[ 3 ] = 0;

	// reset input
	g_p_shared_memory->input.mouse_dx = 0;
	g_p_shared_memory->input.mouse_dy = 0;

	g_p_shared_memory->input.mouse_btn = 0;
	for ( int i = 0; i < 8; ++i ) {
		g_p_shared_memory->input.keyb_state[ i ] = 0;
	}

	// reset peek interface
	g_p_shared_memory->peek.addr_count = 0;
	memset( g_p_shared_memory->peek.addr, 0, GameLink::sSharedMMapPeek_R2::PEEK_LIMIT * sizeof( uint32_t ) );
	memset( g_p_shared_memory->peek.data, 0, GameLink::sSharedMMapPeek_R2::PEEK_LIMIT * sizeof( uint8_t ) );

	// blank frame
	g_p_shared_memory->frame.seq = 0;
	g_p_shared_memory->frame.image_fmt = 0; // = no frame
	g_p_shared_memory->frame.width = 0;
	g_p_shared_memory->frame.height = 0;

	g_p_shared_memory->frame.par_x = 1;
	g_p_shared_memory->frame.par_y = 1;
	memset( g_p_shared_memory->frame.buffer, 0, GameLink::sSharedMMapFrame_R1::MAX_PAYLOAD );

	// audio: 100%
	g_p_shared_memory->audio.master_vol_l = 100;
	g_p_shared_memory->audio.master_vol_r = 100;

	// RAM
	g_p_shared_memory->ram_size = g_membase_size;

	// regs: Windows can hand us a recycled mapping object (crashed master
	// with a client still holding handles) whose old contents survive, so
	// reset the block like every other field group instead of trusting zeros.
	memset( &g_p_shared_memory->regs, 0, sizeof( g_p_shared_memory->regs ) );
}

//
// create_mutex
//
// Create a globally unique mutex.
//
// \returns 1 if we made one, 0 if it failed or the mutex existed already (also a failure).
//
static int create_mutex( const char* p_name )
{

#ifdef WIN32

	// The mutex is already open?
	g_mutex_handle = OpenMutexA( SYNCHRONIZE, FALSE, p_name );
	if ( g_mutex_handle != 0 ) {
		LOG_MSG( "GAMELINK: WARNING: MUTEX \"%s\" already exists, assuming it is left over from a crash.", p_name );
		return 1;
	}

	// Actually create it.
	g_mutex_handle = CreateMutexA( NULL, FALSE, p_name );
	if ( g_mutex_handle ) {
		return 1;
	}

#else // WIN32

	// The mutex is already open?
	g_mutex_handle = sem_open( p_name, 0, 0666, 0 );
	if ( g_mutex_handle != SEM_FAILED )
    {
		LOG_MSG( "GAMELINK: WARNING: MUTEX \"%s\" already exists, assuming it is left over from a crash.", p_name );
		return 1;
	}

	// Actually create it.
	g_mutex_handle = sem_open( p_name, O_CREAT, 0666, 1 );
	if ( g_mutex_handle == SEM_FAILED )
    {
		LOG_MSG( "GAMELINK: Creating MUTEX \"%s\" failed. [sem_open=%d, errno=%d]", p_name, (int)(size_t)g_mutex_handle, errno );
#ifdef MACOSX
		LOG_MSG( "GAMELINK: Might need to manually reboot the system." );
#else // MACOSX
		LOG_MSG( "GAMELINK: Might need to manually tidy up in /dev/shm (or reboot system)." );
#endif // MACOSX
		g_mutex_handle = nullptr;
	}
    else
    {
		return 1;
	}

#endif // WIN32

	return 0;
}

//
// destroy_mutex
//
// Tidy up the mutex.
//
static void destroy_mutex( const char* p_name )
{
#ifdef WIN32

	(void)(p_name);

	if ( g_mutex_handle )
	{
		CloseHandle( g_mutex_handle );
		g_mutex_handle = NULL;
	}

#else // WIN32

	if ( g_mutex_handle )
	{
		sem_close( g_mutex_handle );
		sem_unlink( p_name );
		g_mutex_handle = NULL;
	}

#endif // WIN32
}

//
// create_shared_memory
//
// Create a shared memory area.
//
// \returns 1 if we made one, 0 if it failed.
//
static int create_shared_memory()
{
	const int memory_map_size = MEMORY_MAP_CORE_SIZE + g_membase_size;

#ifdef WIN32

	g_mmap_handle = CreateFileMappingA( INVALID_HANDLE_VALUE, NULL,
			PAGE_READWRITE, 0, memory_map_size,	GAMELINK_MMAP_NAME );

	if ( g_mmap_handle )
	{
		if ( GetLastError() == ERROR_ALREADY_EXISTS )
		{
			// A client from an older protocol generation (or a crashed
			// master's leftover) still holds this named object; the view
			// below may then be smaller than this build's map and the
			// allocation path dies with a misleading size error. Name the
			// real cause so the operator closes the stale process.
			LOG_MSG( "GAMELINK: mapping '%s' already exists - close stale "
					"GameLink processes (older protocol builds keep the "
					"old, smaller object alive)", GAMELINK_MMAP_NAME );
		}

		g_p_shared_memory = reinterpret_cast< GameLink::sSharedMemoryMap_R4* >(
			MapViewOfFile( g_mmap_handle, FILE_MAP_ALL_ACCESS, 0, 0, memory_map_size )
			);

		if ( g_p_shared_memory )
		{
			return 1; // Success!
		}
		else
		{
			// tidy up file mapping.
			CloseHandle( g_mmap_handle );
			g_mmap_handle = NULL;
		}
	}

#else // WIN32

	g_mmap_handle = shm_open( GAMELINK_MMAP_NAME, O_CREAT
#ifndef MACOSX
								| O_TRUNC
#endif // !MACOSX
								| O_RDWR, 0666 );
	g_p_shared_memory = NULL; // defensive

	if ( g_mmap_handle < 0 )
	{
		LOG_MSG( "GAMELINK: shm_open( \"" GAMELINK_MMAP_NAME "\" ) failed. errno = %d", errno );
	}
	else
	{
		// set size
		int r;
		r = ftruncate( g_mmap_handle, memory_map_size );
		if ( r < 0 ) {
			LOG_MSG( "GAMELINK: ftruncate failed with %d. errno = %d", r, errno );
			close( g_mmap_handle );
			g_mmap_handle = -1;
			shm_unlink( GAMELINK_MMAP_NAME );
			g_p_shared_memory = NULL;
			return 0;
		}

		// map to a pointer.
		g_p_shared_memory = reinterpret_cast< GameLink::sSharedMemoryMap_R4* >(
			mmap(nullptr, memory_map_size, PROT_READ | PROT_WRITE, MAP_SHARED, g_mmap_handle, 0)
		);

		if ( g_p_shared_memory == MAP_FAILED )
		{
			LOG_MSG( "GAMELINK: mmap failed. errno = %d", errno );
			close( g_mmap_handle );
			g_mmap_handle = -1;
			shm_unlink( GAMELINK_MMAP_NAME );
			g_p_shared_memory = NULL;
			return 0;
		}

		// success!
		return 1;
	}

#endif // WIN32

	// Failure
	return 0;
}

//
// destroy_shared_memory
//
// Destroy the shared memory area.
//
static void destroy_shared_memory()
{
#ifdef WIN32

	if ( g_p_shared_memory )
	{
		UnmapViewOfFile( g_p_shared_memory );
		g_p_shared_memory = NULL;
	}

	if ( g_mmap_handle )
	{
		CloseHandle( g_mmap_handle );
		g_mmap_handle = NULL;
	}

#else // WIN32

	const int memory_map_size = MEMORY_MAP_CORE_SIZE + g_membase_size;

	if ( g_p_shared_memory )
	{
		munmap( g_p_shared_memory, memory_map_size );
		g_p_shared_memory = NULL;
	}

	if ( g_mmap_handle >= 0 )
	{
		close( g_mmap_handle );
		g_mmap_handle = -1;
	}

	shm_unlink( GAMELINK_MMAP_NAME );

#endif // WIN32

}

//==============================================================================

//------------------------------------------------------------------------------
// GameLink::Init
//------------------------------------------------------------------------------
int GameLink::Init( const bool trackonly_mode )
{
    //LOG_MSG("GAMELINK: Init %i", trackonly_mode);
	int iresult;

	// Store the mode we're in.
	g_trackonly_mode = trackonly_mode;

	// Already initialised?
	if ( g_mutex_handle )
	{
		//LOG_MSG( "GAMELINK: Ignoring re-initialisation." );

		// success
		return 1;
	}

	// Create a fresh mutex.
	iresult = create_mutex( GAMELINK_MUTEX_NAME );
	if ( iresult != 1 )
	{
		// failed.
		return 0;
	}

	return 1;
}

//------------------------------------------------------------------------------
// GameLink::AllocRAM
//------------------------------------------------------------------------------
uint8_t* GameLink::AllocRAM( const uint32_t size )
{
    //LOG_MSG("GAMELINK: AllocRAM %i", size);
	int iresult;
	uint8_t *membase;

	g_membase_size = size;

	if (!sdl.gamelink.enable) {
		membase = (uint8_t*)malloc(g_membase_size);
		return membase;
	}

	// Create a shared memory area.
	iresult = create_shared_memory();
	if ( iresult != 1 )
	{
		destroy_mutex( GAMELINK_MUTEX_NAME );
		// failed.
		return nullptr;
	}

	// Initialise
	shared_memory_init();
	gamelink_live_init();

	GameLink::InitTerminal();

	// Running heartbeat is polled by GFX_Events, not serialized PIC tickers.

	const int memory_map_size = MEMORY_MAP_CORE_SIZE + g_membase_size;
	LOG_MSG( "GAMELINK: Initialised. Allocated %d MB of shared memory.", (memory_map_size + (1024*1024) - 1) / (1024*1024) );

	if (sdl.gamelink.snoop) {
		membase = (uint8_t*)malloc(g_membase_size);
	} else {
		membase = ((uint8_t*)g_p_shared_memory) + MEMORY_MAP_CORE_SIZE;
	}

	// Return RAM base pointer.
	return membase;
}

void GameLink::FreeRAM(void *membase)
{
	// free memory if we did not use shared memory
	if (membase != ((uint8_t*)g_p_shared_memory) + MEMORY_MAP_CORE_SIZE) {
		free(membase);
	}
}

//------------------------------------------------------------------------------
// GameLink::Term
//------------------------------------------------------------------------------
void GameLink::Term()
{
    //LOG_MSG("GAMELINK: Term");

	// SEND ABORT CODE TO CLIENT (don't care if it fails)
	if (!sdl.gamelink.snoop && g_p_shared_memory)
		g_p_shared_memory->version = 0;


	gamelink_live_term();
	destroy_shared_memory();

	destroy_mutex( GAMELINK_MUTEX_NAME );

	g_membase_size = 0;
}

//------------------------------------------------------------------------------
// GameLink::In
//------------------------------------------------------------------------------
int GameLink::In( GameLink::sSharedMMapInput_R2* p_input,
				  GameLink::sSharedMMapAudio_R1* p_audio )
{
	// LOG_MSG("GAMELINK: In");
	int ready = 0;

	if (!sdl.gamelink.snoop && g_p_shared_memory)
	{
		if ( g_trackonly_mode )
		{
			// No input.
			memset( p_input, 0, sizeof( sSharedMMapInput_R2 ) );
		}
		else
		{
			if ( g_p_shared_memory->input.ready )
			{
				// Copy client input out of shared memory
				memcpy( p_input, &( g_p_shared_memory->input ), sizeof( sSharedMMapInput_R2 ) );

				// Clear remote delta, prevent counting more than once.
				g_p_shared_memory->input.mouse_dx = 0;
				g_p_shared_memory->input.mouse_dy = 0;

				g_p_shared_memory->input.ready = 0;

				ready = 1; // Got some input
			}

			// Volume sync, ignore if out of range.
			if ( g_p_shared_memory->audio.master_vol_l <= 100 )
				p_audio->master_vol_l = g_p_shared_memory->audio.master_vol_l;
			if ( g_p_shared_memory->audio.master_vol_r <= 100 )
				p_audio->master_vol_r = g_p_shared_memory->audio.master_vol_r;
		}
	}

	return ready;
}

//------------------------------------------------------------------------------
// GameLink::Out
//------------------------------------------------------------------------------
void GameLink::Out( const uint16_t frame_width,
					const uint16_t frame_height,
					const double source_ratio,
					const bool want_mouse,
					const char* p_program,
					const uint32_t* p_program_hash,
					const uint8_t* p_frame,
					const uint8_t* p_sysmem )
{
	//LOG_MSG("GAMELINK: Out %i %i %i", frame_width, frame_height, g_trackonly_mode);
	// Not initialised (or disabled) ?
	if ( g_p_shared_memory == NULL ) {
		return; // <=== EARLY OUT
	}

	// Create integer ratio
	uint16_t par_x, par_y;
	if ( source_ratio >= 1.0 )
	{
		par_x = 4096;
		par_y = static_cast< uint16_t >( source_ratio * 4096.0 );
	}
	else
	{
		par_x = static_cast< uint16_t >( 4096.0 / source_ratio );
		par_y = 4096;
	}

	// Build flags
	uint8_t flags;

	if ( g_trackonly_mode )
	{
		// Tracking Only - DOSBox handles video/input as usual.
		flags = sSharedMemoryMap_R4::FLAG_NO_FRAME;
	}
	else
	{
		// External Input Mode
		flags = sSharedMemoryMap_R4::FLAG_WANT_KEYB;
		if ( want_mouse )
			flags |= sSharedMemoryMap_R4::FLAG_WANT_MOUSE;
	}

	// Paused?
	if ( is_paused )
		flags |= sSharedMemoryMap_R4::FLAG_PAUSED;


	//
	// Send data?

	// Message buffer
	sSharedMMapBuffer_R1 proc_mech_buffer;
	proc_mech_buffer.payload = 0;

#ifdef WIN32

	DWORD mutex_result;
	mutex_result = WaitForSingleObject( g_mutex_handle, INFINITE );
	if ( mutex_result == WAIT_OBJECT_0 )

#else // WIN32

	int mutex_result;
	mutex_result = sem_wait( g_mutex_handle );
	if ( mutex_result < 0 )
	{
		LOG_MSG( "GAMELINK: MUTEX lock failed with %d. errno = %d", mutex_result, errno );
	}
	else

#endif // WIN32

	{

		if (!sdl.gamelink.snoop) {

			// Set version
			g_p_shared_memory->version = PROTOCOL_VER;

			// Set program
			strncpy( g_p_shared_memory->program, p_program, 256 );
			for ( int i = 0; i < 4; ++i )
			{
				g_p_shared_memory->program_hash[ i ] = p_program_hash[ i ];
			}

			// Store flags
			g_p_shared_memory->flags = flags;

			// Register snapshot (protocol v5). Runs in every Out() context
			// (frame, trackonly, pause ticks) on the emulator thread, but
			// never in snoop mode: a snooping instance must not interleave
			// writes with the owning master.
			gamelink_write_regs_snapshot();
            // Rendering also provides an emulator-thread, mutex-held chance
            // to service requests; the GFX_Events heartbeat covers no drawing.
            gamelink_live_tick();

			if ( g_trackonly_mode == false )
			{
				// Update the frame sequence
				++g_p_shared_memory->frame.seq;

				// Copy frame properties
				g_p_shared_memory->frame.image_fmt = 1; // = 32-bit RGBA
				g_p_shared_memory->frame.width = frame_width;
				g_p_shared_memory->frame.height = frame_height;
				g_p_shared_memory->frame.par_x = par_x;
				g_p_shared_memory->frame.par_y = par_y;

				// Frame Buffer
				uint32_t payload;
				payload = frame_width * frame_height * 4;
				if ( frame_width <= sSharedMMapFrame_R1::MAX_WIDTH && frame_height <= sSharedMMapFrame_R1::MAX_HEIGHT )
				{
					memcpy( g_p_shared_memory->frame.buffer, p_frame, payload );
				}
			}
		} else {
#ifdef DEBUG_SNOOP
			LOG_MSG("Hash: %x %x %x %x Flags: %x",
				g_p_shared_memory->program_hash[0],
				g_p_shared_memory->program_hash[1],
				g_p_shared_memory->program_hash[2],
				g_p_shared_memory->program_hash[3],
				g_p_shared_memory->flags);
#endif
		}

		{

			// Find peek offset
			uint32_t offset = RunningProgramLoadAddress - sdl.gamelink.loadaddr;
			if (sdl.gamelink.snoop || !sdl.gamelink.loadaddr) offset = 0;

			// Peek
			for ( uint32_t pindex = 0;
					pindex < g_p_shared_memory->peek.addr_count &&
					pindex < sSharedMMapPeek_R2::PEEK_LIMIT;
				++pindex )
			{
				// read address
				uint32_t address;
				address = g_p_shared_memory->peek.addr[ pindex ] + offset;

				uint8_t data;
				// valid?
				if ( address < g_membase_size )
				{
					data = p_sysmem[ address ]; // read data
				}
				else
				{
					data = 0; // <-- safe
				}

				if (!sdl.gamelink.snoop) {
					g_p_shared_memory->peek.data[ pindex ] = data;
				} else {
#ifdef DEBUG_SNOOP
					uint8_t seek = g_p_shared_memory->peek.data[ pindex ];
					LOG_MSG("_____ peek: %04x = %i / %i / %i", address, seek, data, address >= g_membase_size?0:*(((uint8_t*)g_p_shared_memory) + MEMORY_MAP_CORE_SIZE + address));
#endif
				}
			}
		}

		int found_addr = 0;

		if (!sdl.gamelink.snoop) {
			// Message Processing.
			ExecTerminal( &(g_p_shared_memory->buf_recv),
						  &(g_p_shared_memory->buf_tohost),
						  &(proc_mech_buffer) );

		} else if (RunningProgramLoadAddress && g_p_shared_memory->peek.addr_count) {
#ifdef DEBUG_SNOOP
			LOG_MSG("Load Address = %06x", RunningProgramLoadAddress);
			int matches = 0;
#endif
			for (decltype(g_membase_size) addr = 0; addr < g_membase_size-1024; addr++) {
				bool match = true;
				auto const base = g_p_shared_memory->peek.addr[ 0 ];
				using addr_count_t = decltype(g_p_shared_memory->peek.addr_count);
				for (addr_count_t i = 0; i < g_p_shared_memory->peek.addr_count; i++) {
					uint8_t seek = g_p_shared_memory->peek.data[ i ];
                    if (g_p_shared_memory->peek.addr[ i ] > 0x10000000) continue;
					auto const oaddr = g_p_shared_memory->peek.addr[ i ] - base + addr;
					if (oaddr >= g_membase_size || p_sysmem[ oaddr ] != seek) {
						match = false;
						break;
					}
				}
				if (match) {
					if (!found_addr) found_addr = RunningProgramLoadAddress - addr + base;
#ifdef DEBUG_SNOOP
					LOG_MSG("Match at %06x, Offset %06x, Original Load Address %06x", addr, addr-base, RunningProgramLoadAddress - addr + base);
					if (matches++ > 10) break;
#else
					// assume first offset is the correct one
					break;
#endif
				}
			}
		}

#ifdef WIN32

		ReleaseMutex( g_mutex_handle );

#else // WIN32

		mutex_result = sem_post( g_mutex_handle );
		if ( mutex_result < 0 ) {
			LOG_MSG( "GAMELINK: MUTEX unlock failed with %d. errno = %d", mutex_result, errno );
		} else {
//			printf( "GAMELINK: MUTEX unlock ok.\n" );
		}

#endif // WIN32

		static int last_addr = 0;
		if (sdl.gamelink.snoop && found_addr && found_addr != last_addr) {
			last_addr = found_addr;
			LOG_MSG("gamelink load address = %i", found_addr);

			char result[256];
			snprintf(result, sizeof(result), "Found possible ram offset. Config setting:\n[sdl]\ngamelink load address = %i",
				found_addr);
            systemmessagebox("Game Link Snoop Success", result, "ok", "info", 1);
		}

		// Mechanical Message Processing, out of mutex.
		if (!sdl.gamelink.snoop && proc_mech_buffer.payload)
			ExecTerminalMech( &proc_mech_buffer );
	}

}

//==============================================================================
#endif // C_GAMELINK

