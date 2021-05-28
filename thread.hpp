/*
	WinAppDbg64
	@sha0coder
	
	Mario Vilas' WinAppDbg port to C++ 64bits
	
	COMPILER FLAGS:
		 -std=C++11
	
	LINKER FLAGS:
		-lpsapi 

*/

#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <dbghelp.h>
#include <shlobj.h>
#include <winver.h>
#include <winbase.h>
#include <ntstatus.h>
#include <math.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <map>

#include "util.hpp"

using namespace std;


//// FLAGS ////

const DWORD overflow 	= 0x800;
const DWORD direction   = 0x400;
const DWORD interrupts  = 0x200;
const DWORD trap        = 0x100;
const DWORD sign        = 0x80;
const DWORD zero        = 0x40;
const DWORD auxiliary   = 0x10;
const DWORD parity      = 0x4;
const DWORD carry       = 0x1;



//// THREAD ////

class Thread {
protected:
	DWORD pid;
	DWORD tid;
	HANDLE hThread;
	void *teb;
	
public:
	Thread(DWORD pid, DWORD tid) {
		this->tid = tid;
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	}
	
	~Thread() {
		CloseHandle(hThread);
	}
	
	void set_teb(void *teb) {
		this->teb = teb;
	}
	
	void *get_teb() {
		return teb;
	}
	
	int get_tid() {
		return tid;
	}
	
	DWORD get_pid() {
		return pid;
	}
	
	HANDLE get_handle() {
		return hThread;
	}
	
	BOOL suspend() {
		DWORD count;
		
		count = SuspendThread(hThread);
		if (count == -1)
			return FALSE;
		return TRUE;
	}
	
	BOOL resume() {
		DWORD count;
		
		count = ResumeThread(hThread);
		if (count == -1)
			return FALSE;
		return TRUE;
	}
	
	void kill() {
		TerminateThread(hThread, 0);
	}
	
	void kill(DWORD code) {
		TerminateThread(hThread, code);
	}
	
	BOOL is_alive() {
		//TODO: implement	
	}
	
	DWORD get_exit_code() {
		DWORD code;
		GetExitCodeThread(hThread, &code);
		return code;
	}
	
	void get_windows() {
		//TODO: EnumThreadWindows() create Window object and vector
	}
	
	CONTEXT get_context() {
		CONTEXT ctx;

		GetThreadContext(hThread, &ctx);
		return ctx;
	}
	
	void set_context(CONTEXT ctx) {
		SetThreadContext(hThread, &ctx);
	}
	
	DWORD64 get_pc() {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.Rip;
	}
		
	void set_pc(void *pc) {
		CONTEXT ctx;	
		
		ctx = get_context();
		ctx.Rip = (DWORD64)pc;
		set_context(ctx);
	}
	
	DWORD64 get_sp() {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.Rsp;
	}

	void set_sp(void *sp) {
		CONTEXT ctx;
		
		ctx = get_context();
		ctx.Rsp = (DWORD64)sp;
		set_context(ctx);
	}
	
	DWORD64 get_fp() {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.Rbp;
	}
	
	void set_fp(void *fp) {
		CONTEXT ctx;
		
		ctx = get_context();
		ctx.Rbp = (DWORD64)fp;
		set_context(ctx);
	}
	
	DWORD get_flags() {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.EFlags;
	}
	
	void set_flags(DWORD flags) {
		CONTEXT ctx;
		
		ctx = get_context();
		ctx.EFlags |= flags;
		set_context(ctx); 
	}
	
	void clear_flags(DWORD flags) {
		CONTEXT ctx;
		
		ctx = get_context();
		ctx.EFlags &= ~flags;
		set_context(ctx); 
	}
	
	DWORD get_flags_mask(DWORD mask) {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.EFlags & mask;
	}
	
	DWORD get_flags_overflow() {
		return get_flags_mask(overflow);
	}
	
	void set_flags_overflow() {
		set_flags(overflow);
	}
	
	void clear_flags_overflow() {
		clear_flags(overflow);
	}
	
	DWORD get_flags_direction() {
		return get_flags_mask(direction);
	}
		
	void set_flags_direction() {
		set_flags(direction);
	}
	
	void clear_flags_direction() {
		clear_flags(direction);
	}
	
	DWORD get_flags_interrupts() {
		return get_flags_mask(interrupts);
	}
	
	void set_flags_interrupts() {
		set_flags(interrupts);
	}
	
	void clear_flags_interrupts() {
		clear_flags(interrupts);
	}
	
	DWORD get_flags_trap() {
		return get_flags_mask(trap);
	}
	
	void set_flags_trap() {
		set_flags(trap);
	}
	
	void clear_flags_trap() {
		clear_flags(trap);
	}
	
	DWORD get_flags_sign() {
		return get_flags_mask(sign);
	}
	
	void set_flags_sign() {
		set_flags(sign);
	}
	
	void clear_flags_sign() {
		clear_flags(sign);
	}
	
	DWORD get_flags_zero() {
		return get_flags_mask(zero);
	}
	
	void set_flags_zero() {
		set_flags(zero);
	}
	
	void clear_flags_zero() {
		clear_flags(zero);
	}
	
	DWORD get_flags_auxiliary() {
		return get_flags_mask(auxiliary);
	}
	
	void set_flags_auxiliary() {
		set_flags(auxiliary);
	}
	
	void clear_flags_auxiliary() {
		clear_flags(auxiliary);
	}
	
	DWORD get_flags_parity() {
		return get_flags_mask(parity);
	}
	
	void set_flags_parity() {
		set_flags(parity);
	}
	
	void clear_flags_parity() {
		clear_flags(parity);
	}
	
	DWORD get_flags_carry() {
		return get_flags_mask(carry);
	}
	
	void set_flags_carry() {
		set_flags(carry);
	}
	
	void clear_flags_carry() {
		clear_flags(carry);
	}
	
	BOOL is_hidden() {
		BOOL check = FALSE;
		ULONG len;
		
		NtQueryInformationThread(hThread, ThreadHideFromDebugger, &check, sizeof(ULONG), &len);
		return check;
	}
	
	THREAD_BASIC_INFORMATION get_tbi() {
		THREAD_BASIC_INFORMATION tbi = {0};
		
		NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
		return tbi;
	}
	
};


