/*

	Debugger Engine
	@sha0coder
	
	WinAppDbg port to C++ 64bits
	
	use -std=C++11

*/


#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <iostream>
#include <vector>

using namespace std;


//// TIB ////

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;


//// FLAGS ////

const DWORD overflow = 0x800;
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
	HANDLE hThread ;
	
public:
	Thread(DWORD pid, DWORD tid) {
		this->tid = tid;
		hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
	}
	
	~Thread() {
		CloseHandle(hThread);
	}
	
	
	int get_tid() {
		return tid;
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
		
	void set_pc(DWORD64 pc) {
		CONTEXT ctx;	
		
		ctx = get_context();
		ctx.Rip = pc;
		set_context(ctx);
	}
	
	DWORD64 get_sp() {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.Rsp;
	}

	void set_sp(DWORD64 sp) {
		CONTEXT ctx;
		
		ctx = get_context();
		ctx.Rsp = sp;
		set_context(ctx);
	}
	
	DWORD64 get_fp() {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.Rbp;
	}
	
	void set_fp(DWORD64 fp) {
		CONTEXT ctx;
		
		ctx = get_context();
		ctx.Rbp = fp;
		set_context(ctx);
	}
	
	DWORD get_flags() {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.EFlags;
	}
	
	DWORD get_flags_mask(DWORD mask) {
		CONTEXT ctx;
		
		ctx = get_context();
		return ctx.EFlags & mask;
	}
	
	DWORD get_flags_overflow() {
		return get_flags_mask(overflow);
	}
	
	DWORD get_flags_direction() {
		return get_flags_mask(direction);
	}
	
	DWORD get_flags_interrupts() {
		return get_flags_mask(interrupts);
	}
	
	DWORD get_flags_trap() {
		return get_flags_mask(trap);
	}
	
	DWORD get_flags_sign() {
		return get_flags_mask(sign);
	}
	
	DWORD get_flags_zero() {
		return get_flags_mask(zero);
	}
	
	DWORD get_flags_auxiliary() {
		return get_flags_mask(auxiliary);
	}
	
	DWORD get_flags_parity() {
		return get_flags_mask(parity);
	}
	
	DWORD get_flags_carry() {
		return get_flags_mask(carry);
	}
	
	BOOL is_hidden() {
		BOOL check = FALSE;
		ULONG len;
		
		NtQueryInformationThread(hThread, ThreadHideFromDebugger, &check, sizeof(ULONG), &len);
		return check;
	}
	
	THREAD_BASIC_INFORMATION get_tbi() {
		THREAD_BASIC_INFORMATION tbi = {0};
		
		NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
		return tbi;
	}
	
};


//// MODULE ////


class Module {
private:
	MODULEENTRY32 me;
	
public:
	Module(MODULEENTRY32 me) {
		this->me = me;
	}
	
	BYTE* get_base() {
		return me.modBaseAddr;
	}
	
	DWORD get_size() {
		return me.dwSize;
	}
	
	DWORD get_global_usage() {
		return me.GlblcntUsage;
	}
	DWORD get_proc_usage() {
		return me.ProccntUsage;
	}
	
	char *get_path() {
		return me.szExePath;
	}
	
	char *get_name() {
		return me.szModule;
	}
	
	
	
};


//// PROCESS ////


class Process {
protected:
	int pid;
	HANDLE hProc = 0;
	vector<Thread *> threads;
	vector<Module *> modules;
	
public:
	Process(int pid) {
		this->pid = pid;
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	}
	
	~Process() {
		for (Thread *t : threads) 
			delete t;
		for (Module *m: modules)
			delete m;
		threads.clear();
		modules.clear();
		CloseHandle(hProc);
	}
	
	int get_pid() {
		return this->pid;
	}
	
	vector<Thread *> get_threads() {
		return threads;
	}
	
	HANDLE get_handle() {
		return hProc;
	}
	
	void kill() {
		TerminateProcess(hProc, 0);
	}
	
	void kill(unsigned int exit_code) {
		TerminateProcess(hProc, exit_code);
	}
	
	void suspend() {
		if (!threads.size())
			scan_threads();
		for (Thread *t: threads) {
			t->suspend();
		}
	}
	
	void resume() {
		if (!threads.size())
			scan_threads();
		for (Thread *t: threads) {
			t->resume();
		}
	}
	
	void scan_threads() {
		HANDLE hndl;
		THREADENTRY32 te;
		
		hndl = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hndl == INVALID_HANDLE_VALUE) {
			cout << "error: cant open threads handle\n" << endl;
			return;
		}
	
		te.dwSize = sizeof(te);
		
		if (!Thread32First(hndl, &te)) {
			cout << "Cannot locate any thread.\n" << endl;
			CloseHandle(hndl);
			return;
		}
		
		do {
			if (pid == te.th32OwnerProcessID) {
				Thread *t = new Thread(pid, te.th32ThreadID);
				threads.push_back(t);
			}
		} while (Thread32Next(hndl, &te));
		
		CloseHandle(hndl);
	}
	
	void scan_modules() {
		MODULEENTRY32 me;
		HANDLE hndl;
		
		hndl = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
		if (hndl == INVALID_HANDLE_VALUE) {
			cout << "error: cant open modules handle\n" << endl;
			return;
		}
		
		if (!Module32First(hndl, &me)) {
			cout << "Cannot locate any thread.\n" << endl;
			CloseHandle(hndl);
			return;
		}
		
		do {
			if (pid == me.th32ProcessID) {
				Module *m = new Module(me);
				modules.push_back(m);
			}
		} while (Module32Next(hndl, &me));
		
	}
	
	BOOL is_debugged() {
		BOOL dbg;
		CheckRemoteDebuggerPresent(hProc, &dbg);
		return dbg;
	}
	
	DWORD get_exit_code() {
		DWORD code;
		GetExitCodeProcess(hProc, &code);
		return code;
	}
	
	void scan() {
		scan_threads();
		scan_modules();
	}
	
	void clear() {
		threads.clear();
		modules.clear();
	}
	
	
	
	
	
};
