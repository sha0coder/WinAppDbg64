/*

	Debugger Engine
	@sha0coder
	
	WinAppDbg port to C++ 64bits
	
	use -std=C++11

*/


#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <dbghelp.h>
#include <shlobj.h>
#include <winver.h>
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

//// MSR registers ////

typedef struct _SYSDBG_VIRTUAL {
    PVOID Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

typedef enum _DEBUG_CONTROL_CODE {
    DebugSysGetTraceInformation=1,
    DebugSysSetInternalBreakpoint, 
    DebugSysSetSpecialCall,
    DebugSysClerSpecialCalls,  
    DebugSysQuerySpecialCalls, 
    DebugSysBreakpointWithStatus,
    DebugSysGetVersion,
    DebugSysReadVirtual = 8, 
    DebugSysWriteVirtual = 9,
    DebugSysReadPhysical = 10,
    DebugSysWritePhysical = 11,
    DebugSysReadControlSpace=12, 
    DebugSysWriteControlSpace, 
    DebugSysReadIoSpace, 
    DebugSysSysWriteIoSpace,
    DebugSysReadMsr,
    DebugSysWriteMsr,
    DebugSysReadBusData,
    DebugSysWriteBusData,
    DebugSysCheckLowMemory, 
} DEBUG_CONTROL_CODE;



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
	int pid;
	MODULEENTRY32 me;
	
public:
	Module(int pid, MODULEENTRY32 me) {
		this->pid = pid;
		this->me = me;
	}
	
	DWORD64 get_base() {
		return (DWORD64)me.modBaseAddr;
	}
	
	BYTE* get_ptr() {
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
	
	HANDLE get_handle() {
		return me.hModule;
	}
	
	DWORD64 load_symbols(HANDLE hProcess, char *pdb_filename) {
		DWORD64 sym_base;
		
		sym_base = SymLoadModuleEx(hProcess, me.hModule, pdb_filename, get_name(),  get_base(), get_size(), NULL, 0);
		return sym_base;
	}
	
	BOOL is_address_here(DWORD64 address) {
		DWORD64 base = get_base();
		if (address >= base && address < base+get_size())
			return TRUE;
		return FALSE;
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
	
	vector<Module *> get_modules() {
		return modules;
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
			cout << "error: cant open modules handle" << endl;
			return;
		}
		
		me.dwSize = sizeof(me);
		
		if (!Module32First(hndl, &me)) {
			cout << "Cannot locate any module." << GetLastError() << endl;
			CloseHandle(hndl);
			return;
		}
		
		do {
			if (pid == me.th32ProcessID) {
				Module *m = new Module(pid, me);
				modules.push_back(m);
			}
		} while (Module32Next(hndl, &me));
		
		CloseHandle(hndl);
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
	
	Module *get_module_by_name(char *module_name) {
		for (auto m : modules) {
			if (strcmp(m->get_name(), module_name) == 0) {
				return m;
			}
		}
		return NULL;
	}
	
};

//// Window ////

class Window {
protected:
	HWND hWin;
public:
	Window(HWND hWin) {
		this->hWin = hWin;
	}
	
	
};


//// System ////

class System {
protected:
public:
	System() {
	}
	
	Window *find_window(char *clsname, char *winname) {
		HWND hWin;
		
		hWin = FindWindowA(clsname, winname);
		Window *win = new Window(hWin);
		
		return win;
	}
	
	Window *get_window_at_xy(long x, long y) {
		HWND hWin;
		POINT point;
		
		point.x = x;
		point.y = y;
		hWin = WindowFromPoint(point);
		Window *win = new Window(hWin);
		
		return win;
	}
	
	Window *get_foreground_window() {
		HWND hWin;
		
		hWin = GetForegroundWindow();
		Window *win = new Window(hWin);
		
		return win;
	}
	
	Window *get_desktop_window() {
		HWND hWin;
		
		hWin = GetDesktopWindow();
		Window *win = new Window(hWin);
		
		return win;
	}
	
	Window *get_shell_window() {
		HWND hWin;
		
		hWin = GetShellWindow();
		Window *win = new Window(hWin);
		
		return win;
	}
	
	get_top_level_windows(WNDENUMPROC callback) {
		EnumWindows(callback, 0);
	}
	
	BOOL adjust_privileges(TOKEN_PRIVILEGES new_state) {
		HANDLE token;
		
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
			AdjustTokenPrivileges(token, FALSE, &new_state, sizeof(new_state), NULL, NULL);
			CloseHandle(token);
			return TRUE;
		}
		return FALSE;
	}
	
	BOOL is_admin() {
		return IsUserAnAdmin();
	}
	
	BOOL set_kill_on_exit_mode(BOOL mode) {
		// won't work before calling CreateProcess or DebugActiveProcess
		try {
			DebugSetProcessKillOnExit(mode);
		} catch(...) {
			return FALSE;	
		}
		return TRUE;
	}
	
	char *read_msr(PVOID address) {
		typedef LONG (NTAPI *NtSystemDebugControl) (int,void*,DWORD,void*,DWORD,DWORD*);
		NtSystemDebugControl ntSystemDebugControl;
		SYSDBG_VIRTUAL mem;
		
		mem.Address = address;
		mem.Buffer = 0;
		
		ntSystemDebugControl = (NtSystemDebugControl)GetProcAddress(LoadLibrary("ntdll"),"NtSystemDebugControl");
		ntSystemDebugControl(DebugSysReadMsr, &mem, sizeof(mem), &mem, sizeof(mem), NULL);
		
		return (char *)mem.Buffer;
	}
	
	void write_msr(void *address, void *buffer) {
		typedef LONG (NTAPI *NtSystemDebugControl) (int,void*,DWORD,void*,DWORD,DWORD*);
		NtSystemDebugControl ntSystemDebugControl;
		SYSDBG_VIRTUAL mem;
		
		mem.Address = address;
		mem.Buffer = buffer;
		
		ntSystemDebugControl = (NtSystemDebugControl)GetProcAddress(LoadLibrary("ntdll"),"NtSystemDebugControl");
		ntSystemDebugControl(DebugSysReadMsr, &mem, sizeof(mem), &mem, sizeof(mem), NULL);
	}
	
	DWORD reg_read_dword(HKEY hKeyParent, char *subkey, char *value_name) {
		HKEY hKey;
		DWORD data = 0;
		DWORD len = sizeof(DWORD);
		
		if (RegOpenKeyEx(hKeyParent, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegQueryValueEx(hKey, value_name, NULL, NULL, (LPBYTE)(&data), &len);
			RegCloseKey(hKey);
		}
		
		return data;
	}
	
	void reg_write_dword(HKEY hKeyParent, char *subkey, char *value_name, DWORD value) {
		HKEY hKey;
		DWORD data = 0;
		DWORD len = sizeof(DWORD);
		
		if (RegOpenKeyEx(hKeyParent, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegSetValueEx(hKey, value_name, 0, REG_DWORD, reinterpret_cast<BYTE *>(&value), sizeof(DWORD));
			RegCloseKey(hKey);
		}
	}
	
	
	char *reg_read_str(HKEY hKeyParent, char *subkey, char *value_name) {
		HKEY hKey;
		DWORD data = 0;
		DWORD len = sizeof(DWORD);
		
		if (RegOpenKeyEx(hKeyParent, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegQueryValueEx(hKey, value_name, NULL, NULL, (LPBYTE)(&data), &len);
			RegCloseKey(hKey);
		}
		
		return data;
	}
	
	void reg_write_str(HKEY hKeyParent, char *subkey, char *value_name, char *value, ULONG value_len) {
		HKEY hKey;
		DWORD data = 0;
		DWORD len = sizeof(DWORD);
		
		if (RegOpenKeyEx(hKeyParent, subkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegSetValueEx(hKey, value_name, 0, REG_DWORD, reinterpret_cast<BYTE *>(&value), value_len);
			RegCloseKey(hKey);
		}
	}
	
	
	
	
	
	
};

//// Debug //// 


class Debug {
protected:
	int pid;
	System *sys;
	
public:
	Debug() {
		sys = new System();
	}
	
	Process *attach(int pid) {
		if (DebugActiveProcess(pid)) {
			Process *p = new Process(pid);
			p->scan();
			this->pid = pid;
			return p;
		}
		
		return NULL;
	}
	
	void detach() {
		DebugActiveProcessStop(pid);
	}
	
	void exec(char *file_name, char **args) {
		//system->start_process(file_name, args);
	}
	
};

