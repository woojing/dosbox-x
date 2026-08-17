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

/* Debugger IPC server: loopback TCP JSON-lines control channel.
 *
 * The server is serviced exclusively from the stop branch of
 * DEBUG_Loop() (single-threaded with the emulator core), so guest state
 * is never accessed concurrently. A single sequential client is
 * supported; connections are accepted only while the guest is stopped.
 * Responses and events use non-blocking sends with a finite buffer.
 *
 * See docs/dosbox_debugger_ipc_plan.md in the koei_hero repository for
 * the design contract this implements. */

#ifndef DOSBOX_DEBUG_IPC_H
#define DOSBOX_DEBUG_IPC_H

#if C_DEBUG

/* Called once from GUI_StartUp() when [sdl] debug server = true.
 * port 0 picks an ephemeral port; the bound port is logged immediately
 * (before any debugger console can exist) so launchers can parse it
 * from the boot log. break_port opens a second, dedicated listener whose
 * only accepted request is "break_request" (v1.1 forced-stop channel,
 * serviced by a background thread while the guest runs); also 0 =
 * ephemeral, also logged. */
void DEBUG_IPC_StartUp(int port, int break_port);

/* Test-and-clear the break_request flag. Call from GFX_Events(); a
 * non-zero return means the caller should invoke DEBUG_EnableDebugger()
 * (NOT DEBUG_Enable_Handler, which toggles) to stop the guest. */
int DEBUG_IPC_BreakRequested(void);

/* One non-blocking service step. Call from the DEBUG_Loop() stop branch
 * every iteration: accepts a pending client, drains complete request
 * lines, executes all queued commands in order and flushes output.
 * Returns -1 when an executed command (continue/quit) requires
 * DEBUG_Loop to return immediately, 0 otherwise. */
int DEBUG_IPC_Poll(void);

/* State events (authoritative; replaces screen-scraping stop probes).
 * Best-effort immediate non-blocking flush. */
void DEBUG_IPC_NotifyStopped(void);
void DEBUG_IPC_NotifyRunning(void);

/* Stop-reason instrumentation: call right before DEBUG_EnableDebugger()
 * at each entry point. Values used: initial_break, breakpoint,
 * int_breakpoint, step, break_request. */
void DEBUG_IPC_SetStopReason(const char* reason);

/* --- Guest-state hooks, implemented in debug.cpp --- */

/* Create breakpoints; returns an opaque handle (CBreakpoint*). */
void* DEBUG_IPC_BPAddCode(uint16_t seg, uint32_t off);
void* DEBUG_IPC_BPAddInt(uint8_t int_nr, int ah, int al); /* ah/al < 0 = wildcard */

bool DEBUG_IPC_BPDelete(void* handle);
void DEBUG_IPC_BPDeleteAll(void);

/* Walk the global breakpoint list by index (0-based). kind: 0 = code,
 * 1 = interrupt, 2 = other (memory etc.). ah/al are -1 when not
 * applicable or wildcard. */
bool DEBUG_IPC_BPGet(int index, void** handle, int* kind, uint16_t* seg,
                     uint32_t* off, int* int_nr, int* ah, int* al);

/* Single-step one instruction (keyboard F11 equivalent). */
bool DEBUG_IPC_DoStep(void);

const char* DEBUG_IPC_CoreName(void);

#endif /* C_DEBUG */
#endif /* DOSBOX_DEBUG_IPC_H */
