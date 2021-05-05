/*
	WinAppDbg64
	@sha0coder
	
	Mario Vilas' WinAppDbg port to C++ 64bits
	
	COMPILER FLAGS:
		 -std=C++11
	
	LINKER FLAGS:
		-lpsapi 
	
	TODO:
		- breakpoints
		- interactive console mode
		
	BUGS:
		- if the process is launched by debugger, it can't scan the modules, if it's attached it can scan.
			it's a 229 error opening the handle.


	OBJECTS:
	
			  +--> breakpoints --> Breakpoint	  
              |
	         Debug --> events --> Event
	          |
System --->	Process -> threads --> Thread
   |	         |
   |             +--> modules --> Module
   +---> services --> Service
   |
   +---> Window
   
   
*/


#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <dbghelp.h>
#include <shlobj.h>
#include <winver.h>
#include <winbase.h>
#include <psapi.h>
#include <iostream>
#include <vector>

using namespace std;

#define EXCEPTION_WX86_BREAKPOINT 0x4000001F

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
		
		NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
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
	
	void *get_entry_point(HANDLE hProc) {		
		MODULEINFO modinfo;
		
		GetModuleInformation(hProc, me.hModule, &modinfo, 0);
		
		return modinfo.EntryPoint;
	}
};


//// PROCESS ////


class Process {
protected:
	int pid;
	HANDLE hProc = 0;
	vector<Thread *> threads;
	vector<Module *> modules;
	PROCESSENTRY32 entry;
	
public:
	Process(int pid) {
		this->pid = pid;
		hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProc == NULL)
			cout << "process handle null " << endl;
		calc_entry();
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
	
	void calc_entry() {
		HANDLE hSnapshot;
		PROCESSENTRY32 pe32;
		 
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    	if (hSnapshot) {
	        pe32.dwSize = sizeof(PROCESSENTRY32);
	        if(Process32First(hSnapshot, &pe32)) {
	            do {
	            	
	            	if (pe32.th32ProcessID == this->pid) {
	            		this->entry = pe32;
	            		break;
					}

	            } while(Process32Next(hSnapshot, &pe32));
	         }
	         CloseHandle(hSnapshot);
	    }
	}
	
	string get_name() {
		string str(entry.szExeFile);
		return str;
	}
	
	int get_ppid() {
		this->entry.th32ParentProcessID;
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
	
	HANDLE get_handle(DWORD perms) {
		return OpenProcess(perms, TRUE, pid);
	}
	
	void kill() {
		kill(0);
	}
	
	void kill(unsigned int exit_code) {
		HANDLE hTerm;
		
		// With PROCESS_ALL_ACCESS handle dont work, the PROCESS_TERMINATE access is needed.
		
		hTerm = OpenProcess(PROCESS_TERMINATE, TRUE, pid);
		TerminateProcess(hTerm, exit_code);
			
		CloseHandle(hTerm);
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
		
		threads.clear();
		
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
		
		hndl = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
		if (hndl == INVALID_HANDLE_VALUE) {
			cout << "error: cant open modules handle err:" << GetLastError() << endl;
			return;
		}
		
		me.dwSize = sizeof(me);
		
		if (!Module32First(hndl, &me)) {
			cout << "Cannot locate any module." << GetLastError() << endl;
			CloseHandle(hndl);
			return;
		}
		
		modules.clear();
		
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
	
	BOOL is_alive() {
		if (WaitForSingleObject(hProc, 0) == WAIT_TIMEOUT)
			return TRUE;
		return FALSE;
	}
	
	DWORD wait(DWORD millis) {
		return WaitForSingleObject(hProc, 0);
	}
	
	void flush_instruction_cache() {
		scan_modules();
		FlushInstructionCache(hProc, modules[0]->get_ptr(), entry.dwSize);
	}
	
	void debug_break() {
		// trigger system breakpoint on the process
		
		DebugBreakProcess(hProc);
	}
	
	FILETIME get_start_time() {
		FILETIME creat;
		
		GetProcessTimes(hProc, &creat, NULL, NULL, NULL);
		return creat;
	}
	
	FILETIME get_exit_time() {
		FILETIME exit;
		
		GetProcessTimes(hProc, NULL, &exit, NULL, NULL);
		return exit;
	}
	
	FILETIME get_kernel_time() {
		FILETIME kernel;
		
		GetProcessTimes(hProc, NULL, NULL, &kernel, NULL);
		return kernel;
	}
	
	FILETIME get_user_time() {
		FILETIME user;
		
		GetProcessTimes(hProc, NULL, NULL, NULL, &user);
		return user;
	}
	
	long get_running_time() {
		FILETIME start, exit, time;
		unsigned long long start_time, exit_time, running_time;
		
		start = get_start_time();
		
		if (is_alive()) 
			GetSystemTimeAsFileTime(&exit);
		else
			exit = get_exit_time();
			
		
		start_time = start.dwLowDateTime + ((unsigned long long)start.dwHighDateTime << 32);
		exit_time = exit.dwLowDateTime + ((unsigned long long)exit.dwHighDateTime << 32);
		running_time = exit_time - start_time;
		
		return running_time / 10000;  // 100 nanoseconds steps => milliseconds
	}
	
	/*
		this is only 32bits
	
	DWORD get_dep_policy() {
		BOOL permanent;
		DWORD flags;
		HANDLE hndl;
		
		hndl = get_handle(PROCESS_QUERY_INFORMATION);
		GetProcessDEPPolicy(hndl, &flags, &permanent);
		CloseHandle(hndl);
		
		
		//   return the following values:
        //     - 0: DEP is disabled for this process.
        //     - 1: DEP is enabled for this process.
        //     - 2: DEP-ATL thunk emulation is disabled for this process.
		//
		//	if permanent is true the DEP settings cannot be changed in runtime for this process.
		
		
		return flags;
	}
	
	BOOL is_dep_permanent() {
		BOOL permanent;
		DWORD flags;
		HANDLE hndl;
		
		hndl = get_handle(PROCESS_QUERY_INFORMATION);
		GetProcessDEPPolicy(hndl, &flags, &permanent);
		CloseHandle(hndl);
		
		// if permanent is true the DEP settings cannot be changed in runtime for this process.
		
		return permanent;
	}*/
	
	PEB *get_peb_address() {
		HANDLE hndl;
		PROCESSINFOCLASS infocls;
		PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();
		ULONG rlen;
		ULONG pinfo_len = sizeof(PROCESS_BASIC_INFORMATION);
		
		
		hndl = get_handle(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
		NtQueryInformationProcess(hndl, ProcessBasicInformation, pBasicInfo, pinfo_len, &rlen);
		CloseHandle(hndl);
		
		return pBasicInfo->PebBaseAddress;
	}
	
	PEB get_peb() {
		return *get_peb_address();
	}
	
	void *get_entry_point() {
		HANDLE hndl;
		void *entry;
		
		scan_modules();
		if (modules.size() == 0)
			return NULL;
			
		hndl = get_handle(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
		entry = modules[0]->get_entry_point(hndl);
		CloseHandle(hndl);
		
		return entry;
	}
	
	Module *get_main_module() {
		scan_modules();
		if (modules.size() == 0)
			return NULL;
		
		return modules[0];
	}
	
	void *get_image_base() {
		Module *mod = get_main_module();
		if (mod != NULL) {
			//TODO: ?
		}
		return NULL; //get_peb().ImageBaseAddress;
	}
	
	MEMORY_BASIC_INFORMATION mquery(void *address) {
		HANDLE hndl;
		MEMORY_BASIC_INFORMATION mbi;
		
		// call this with a try/catch
		// http://winapi.freetechsecrets.com/win32/WIN32MEMORYBASICINFORMATION.htm
	
		hndl = get_handle(PROCESS_QUERY_INFORMATION);
		VirtualQueryEx(hndl, address, &mbi, sizeof(mbi));
		CloseHandle(hndl);

		return mbi;
	}
	
	DWORD mprotect(void *address, SIZE_T size, DWORD prot) {
		HANDLE hndl;
		DWORD prev_prot;
		
		hndl = get_handle(PROCESS_VM_OPERATION);
		VirtualProtectEx(hndl, address, size, prot, &prev_prot);
		CloseHandle(hndl);
		
		return prev_prot;
	}
	
	void write(void *address, void *buff, SIZE_T size) {
		poke(address, buff, size);
	}
	
	void poke(void *address, void *buff, SIZE_T size) {
		MEMORY_BASIC_INFORMATION mbi;
		HANDLE hndl;
		SIZE_T len;
		DWORD prot = 0;

		try {
			mbi = mquery(address);
		} catch(...) {
			cout << "/!\\ invalid address" << endl;
			return;
		}
		
		if (mbi.Type & MEM_IMAGE || mbi.Type & MEM_MAPPED)
			prot |= PAGE_WRITECOPY;
		
		if (mbi.AllocationProtect & PAGE_READWRITE || mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
			prot = 0;
		
		else if (mbi.AllocationProtect & PAGE_EXECUTE_READ || mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
			prot = PAGE_EXECUTE_READWRITE;
			
		else 
			prot = PAGE_READWRITE;
			
			
		if (prot) {
			mprotect(address, size, prot);
		}

		hndl = get_handle(PROCESS_VM_WRITE);
		if (!WriteProcessMemory(hndl, address, buff, size, &len))
			cout << "cant write memory of process " << this->pid << endl;
		CloseHandle(hndl);
		
		if (size != len)
			cout << "process write " << len << " instead of " << size << endl;
		
		//TODO: restore previous privileges?
	}
	
	void read(void *address, void *buff, SIZE_T size) {
		HANDLE hndl;
		SIZE_T len;
		
		hndl = get_handle(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
		if (!ReadProcessMemory(hndl, address, buff, size, &len))
			cout << "cant read memory of process " << this->pid << endl;
		CloseHandle(hndl);
		
		if (size != len)
			cout << "process read " << len << " instead of " << size << endl;
		
	}
	
	char read_char(void *address) {
		char buff[2];
		
		read(address, buff, 1);
		
		return buff[0];
	}
	
	void write_char(void *address, char c) {
		char buff[3];
		
		buff[0] = c;
		
		write(address, buff, 1);
	}
	
	int read_int(void *address) {
		int value;
		
		read(address, (void *)&value, sizeof(int));
		
		return value;
	}
	
	void write_int(void *address, int value) {
		write(address, (void *)&value, sizeof(int));
	}
	
	short read_short(void *address) {
		short value;
		
		read(address, (void *)&value, sizeof(short));
		
		return value;
	}
	
	void write_short(void *address, short value) {
		write(address, (void *)&value, sizeof(short));
	}
	
	unsigned short read_unsigned_short(void *address) {
		unsigned short value;
		
		read(address, (void *)&value, sizeof(unsigned short));
		
		return value;
	}
	
	void write_unsigned_short(void *address, unsigned short value) {
		write(address, (void *)&value, sizeof(unsigned short));
	}
	
	unsigned int read_uint(void *address) {
		unsigned int value;
		
		read(address, (void *)&value, sizeof(unsigned int));
		
		return value;
	}
	
	void write_uint(void *address, unsigned int value) {
		write(address, (void *)&value, sizeof(unsigned int));
	}
	
	float read_float(void *address) {
		float value;
		
		read(address, (void *)&value, sizeof(float));
		
		return value;
	}
	
	void write_float(void *address, float value) {
		write(address, (void *)&value, sizeof(float));
	}
	
	double read_double(void *address) {
		double value;
		
		read(address, (void *)&value, sizeof(double));
		
		return value;
	}
	
	void write_double(void *address, double value) {
		write(address, (void *)&value, sizeof(double));
	}
	
	long read_long(void *address) {
		long value;
		
		read(address, (void *)&value, sizeof(long));
		
		return value;
	}
	
	void write_long(void *address, long value) {
		write(address, (void *)&value, sizeof(long));
	}
	
	unsigned long  read_unsigned_long(void *address) {
		unsigned long value;
		
		read(address, (void *)&value, sizeof(unsigned long));
		
		return value;
	}
	
	void write_unsigned_long(void *address, unsigned long value) {
		write(address, (void *)&value, sizeof(unsigned long));
	}
	
	long long read_long_long(void *address) {
		long long value;
		
		read(address, (void *)&value, sizeof(long long));
		
		return value;		
	}
	
	void write_long_long(void *address, long long value) {
		write(address, (void *)&value, sizeof(long long));
	}
	
	void *read_pointer(void *address) {
		void *pointer;
		
		read(address, &pointer, sizeof(void *));
		
		return pointer;
	}
	
	void write_pointer(void *address, void *pointer) {
		write(address, &pointer, sizeof(void *));
	}
	
	void free(void *address) {
		HANDLE hndl;
		
		hndl = get_handle(PROCESS_VM_OPERATION);
		VirtualFreeEx(hndl, address, 0, MEM_RELEASE);
		CloseHandle(hndl);
	}
	
	BOOL is_pointer(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		return TRUE;
	}
	
	BOOL is_address_valid(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		return TRUE;
	}
	
	BOOL is_address_free(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.State & MEM_FREE)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_reserved(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.State & MEM_RESERVE)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_commited(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.State & MEM_COMMIT)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_guard(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {   
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.AllocationProtect & PAGE_GUARD)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_readable(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {   
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.AllocationProtect & PAGE_READONLY || 
			mbi.AllocationProtect & PAGE_READWRITE ||
			mbi.AllocationProtect & PAGE_EXECUTE_READ ||
			mbi.AllocationProtect & PAGE_EXECUTE_READWRITE
			)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_writeable(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {   
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.AllocationProtect & PAGE_READWRITE || 
			mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_copy_on_write(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {   
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.AllocationProtect & PAGE_WRITECOPY || 
			mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_executable(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {   
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.AllocationProtect & PAGE_EXECUTE_READ || 
			mbi.AllocationProtect & PAGE_EXECUTE_READWRITE ||
			mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_address_executable_and_writeable(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		
		try {   
			mbi = mquery(address);	
		} catch(...) {
			return FALSE;
		}
		
		if (mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
			return TRUE;
		return FALSE;
	}
	
	
	
	
	
	
	
	
	
	
}; // end Process

//// Window ////

class Window {
protected:
	HWND hWin;
public:
	Window(HWND hWin) {
		this->hWin = hWin;
	}
}; // end Window

//// Service ////

class Service {
protected:
	ENUM_SERVICE_STATUS_PROCESS stat;
	
public:
	Service(ENUM_SERVICE_STATUS_PROCESS stat) {
		this->stat = stat;
	}
	
	ENUM_SERVICE_STATUS_PROCESS get_stat() {
		return stat;
	}
	
	string get_name() {
		string str(stat.lpServiceName);
		return str;
	}
	
	char *get_display_name() {
		return stat.lpDisplayName;
	}
	
	DWORD get_exit_code() {
		return stat.ServiceStatusProcess.dwWin32ExitCode;
	}
	
	int get_pid() {
		return stat.ServiceStatusProcess.dwProcessId;
	}
	
	SC_HANDLE open_scm(DWORD access) {
		return OpenSCManagerA(NULL, NULL, access);
	}
	
	SC_HANDLE open_service(SC_HANDLE scm, DWORD access) {
		return OpenServiceA(scm, stat.lpServiceName, access);
	}
	
	void change_description(string description) {
		SC_HANDLE scm;
		SC_HANDLE hService;
		SERVICE_DESCRIPTION sd;
		
		sd.lpDescription = (LPSTR)description.c_str();
		
		scm = open_scm(SC_MANAGER_ALL_ACCESS);
		if (scm) {
			hService = open_service(scm, SERVICE_CHANGE_CONFIG);
			if (hService) {
				
				ChangeServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, &sd);
				
				CloseServiceHandle(hService);
			}	
			CloseServiceHandle(scm);
		}
	}
	
	DWORD get_current_state() {
		return stat.ServiceStatusProcess.dwCurrentState;
	}
	
	BOOL is_running() {
		if (stat.ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING)
			return TRUE;
		return FALSE;		
	}
	
	BOOL is_paused() {
		if (stat.ServiceStatusProcess.dwCurrentState == SERVICE_PAUSED)
			return TRUE;
		return FALSE;		
	}
	
	BOOL is_stopped() {
		if (stat.ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED)
			return TRUE;
		return FALSE;		
	}
	
	void start() {
		SC_HANDLE scm;
		SC_HANDLE hService;
		
		scm = open_scm(SC_MANAGER_ALL_ACCESS);
		if (scm) {
			hService = open_service(scm, SERVICE_ALL_ACCESS);
			if (hService) {
				StartServiceA(hService, 0, NULL);
				CloseServiceHandle(hService);
			}
			CloseServiceHandle(scm);
		}
	}
	
	void stop() {
		SC_HANDLE scm;
		SC_HANDLE hService;
		
		scm = open_scm(SC_MANAGER_ALL_ACCESS);
		if (scm) {
			hService = open_service(scm, SERVICE_ALL_ACCESS);
			if (hService) {
				ControlService(hService, SERVICE_CONTROL_STOP, NULL);
				CloseServiceHandle(hService);
			}
			CloseServiceHandle(scm);
		}
	}
	
	void restart() {
		stop();
		start();
	}
	
	void pause() {
		SC_HANDLE scm;
		SC_HANDLE hService;
		
		scm = open_scm(SC_MANAGER_ALL_ACCESS);
		if (scm) {
			hService = open_service(scm, SERVICE_ALL_ACCESS);
			if (hService) {
				ControlService(hService, SERVICE_CONTROL_PAUSE, NULL);
				CloseServiceHandle(hService);
			}
			CloseServiceHandle(scm);
		}
	}
	
	void resume() {
		SC_HANDLE scm;
		SC_HANDLE hService;
		
		scm = open_scm(SC_MANAGER_ALL_ACCESS);
		if (scm) {
			hService = open_service(scm, SERVICE_ALL_ACCESS);
			if (hService) {
				ControlService(hService, SERVICE_PAUSE_CONTINUE, NULL);
				CloseServiceHandle(hService);
			}
			CloseServiceHandle(scm);
		}
	}
	
}; // end Service


//// System ////

class System {
protected:
	vector<Service *> services;
	vector<Process *> processes;
	
public:
	System() {
	}
	
	~System() {
		for (auto service: services) {
			delete service;
		}
		services.clear();
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
	
	DWORD reg_read_dword(HKEY hKeyParent, string subkey, char *value_name) {
		HKEY hKey;
		DWORD data = 0;
		DWORD len = sizeof(DWORD);
		
		if (RegOpenKeyEx(hKeyParent, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			RegQueryValueEx(hKey, value_name, NULL, NULL, (LPBYTE)(&data), &len);
			RegCloseKey(hKey);
		}
		
		return data;
	}
	
	void reg_write_dword(HKEY hKeyParent, string subkey, string value_name, DWORD value) {
		HKEY hKey;		
		
		if (RegOpenKeyEx(hKeyParent, subkey.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
			RegSetValueEx(hKey, value_name.c_str(), 0, REG_DWORD, (BYTE *)&value, sizeof(DWORD));
			RegCloseKey(hKey);
		}
	}
	
	
	ULONG reg_read_str(HKEY hKeyParent, string subkey, string value_name, char *out_str, DWORD len) {
		HKEY hKey;
		
		if (RegOpenKeyExA(hKeyParent, subkey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
			if (RegQueryValueExA(hKey, value_name.c_str(), NULL, NULL, (LPBYTE)out_str, &len) != ERROR_SUCCESS) {
				if (GetLastError() == 0)
					cout << "need permissions." << endl;
				else
					cout << "wrong value name " << GetLastError() << endl;
			}
			RegCloseKey(hKey);
		} else {
			cout << "wrong subkey " << GetLastError() << endl;
		}
		
		return len;
	}
	
	void reg_write_str(HKEY hKeyParent, string subkey, string value_name, string value) {
		HKEY hKey;
		
		if (RegOpenKeyExA(hKeyParent, subkey.c_str(), 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
			if (RegSetValueExA(hKey, value_name.c_str(), 0, REG_SZ, (BYTE *)value.c_str(), value.size()) != ERROR_SUCCESS) {
				if (GetLastError() == 0)
					cout << "need permissions." << endl;
				else
					cout << "wrong value_name " << GetLastError() << endl;
			}

			RegCloseKey(hKey);
		} else {
			cout << "wrong subkey " << GetLastError() << endl;
		}
	}
	
	void reg_delete_value(HKEY hKeyParent, string subkey, string value_name) {
		HKEY hKey;
		if (RegOpenKeyExA(hKeyParent, subkey.c_str(), 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
			RegDeleteValueA(hKey, value_name.c_str());
		} else {
			cout << "wrong subkey " << GetLastError() << endl;
		}
	}
	
	char *get_postmortem_debugger() {
		char *dbg = (char *)malloc(1024);
		if (dbg == NULL)
			return NULL;
		
		reg_read_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Debugger", dbg, 1024);
		
		return dbg;
	}
	
	void set_postmortem_debugger(string dbg) {
		reg_write_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Debugger", dbg);
	}
	
	
	void auto_postmortem() {
		// dont need a confirmation before launching the debugger.
		reg_write_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Auto", "1");
	}
	
	void noauto_postmortem() {
		// need a confirmation before launching the debugger.
		reg_write_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Auto", "0");
	}
	
	BOOL is_auto_postmortem() {
		char automatic[5];
		
		reg_read_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Auto", (char *)automatic, 5);
		if (automatic[0] == '1')
			return TRUE;
		return FALSE;
	}
	
	void add_exclussion_list(string progname) {
		reg_write_dword(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList", progname, 1);
	}
	
	void del_exclussion_list(string progname) {
		reg_delete_value(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\AutoExclusionList", progname); 
	}
	
	vector<Service *> get_services() {
		return services;
	}
	
	void scan_services() {
		SC_HANDLE scm;
		SC_HANDLE hService;
		void *buff = NULL;
		DWORD buff_sz = 0;
		DWORD more_bytes_needed, service_count;
		
		services.clear();
		
		scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
		if (scm) {
			for (;;) {
				if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)buff, buff_sz, &more_bytes_needed, &service_count, NULL, NULL)) {
					ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)buff;
					
					for (int i = 0; i < service_count; i++) {
						ENUM_SERVICE_STATUS_PROCESS stat = services[i];
						Service *service = new Service(stat);
						this->services.push_back(service);
					}
					
					free(buff);
					CloseHandle(scm);
					return;
				}
			
			    if (GetLastError() != ERROR_MORE_DATA) {
			      free(buff);
			      return;
			    }
			    
			    buff_sz += more_bytes_needed;
			    free(buff);
			    buff = malloc(buff_sz);
			    CloseHandle(scm);
			}
		}
	}
	
	Service *get_service_by_name(string name) {
		for (Service *service : services) {
			if (service->get_name() == name) {
				return service;
			}
		}
		return NULL;
	}
	
	void scan_processes() {
		HANDLE hSnapshot;
		PROCESSENTRY32 pe32;
		
	    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	    if (hSnapshot) {
	        pe32.dwSize = sizeof(PROCESSENTRY32);
	        if (Process32First(hSnapshot, &pe32)) {
	            do {
	            	Process *process = new Process(pe32.th32ProcessID);	
	            	processes.push_back(process);
	            } while(Process32Next(hSnapshot, &pe32));
	        }
	        CloseHandle(hSnapshot);
	    }
	}
	
	Process *get_process_by_name(string process_name) {
		for (auto process: processes) {
			if (process->get_name() == process_name) {
				return process;
			}
		}
		return NULL;
	}
	
	int get_explorer_pid() {
		scan_processes();
		auto explorer = get_process_by_name("explorer.exe");
		if (explorer != NULL)
			return explorer->get_pid();
			
		return 0;
	}
	
	vector<Process *>get_processes() {
		return processes;
	}
	
}; // end System

class Event {
protected:
	Process *process;
	DEBUG_EVENT ev;
	string name;
	DWORD continue_status;
	
public:
	Event(DEBUG_EVENT ev, Process *process) {
		this->ev = ev;
		this->process = process;
	}
	
	~Event() {
		delete process;
	}
	
	string get_name() {
		return name;
	}
	
	void set_continue_status(DWORD status) {
		this->continue_status = status;
	}
	
	DWORD get_continue_status() {
		return continue_status;
	}
	
	DWORD get_event_code() {
		return ev.dwDebugEventCode;
	}
	
	DWORD get_exception_code() {
		return ev.u.Exception.ExceptionRecord.ExceptionCode;
	}
	
	DWORD get_rip_type() {
		return ev.u.RipInfo.dwType;
	}
	
	DWORD get_pid() {
		return ev.dwProcessId;
	}
	
	DWORD get_tid() {
		return ev.dwThreadId;
	}
	
	Process *get_process() {
		return process;
	}

	
}; // end Event


//// Breakpoint ////

typedef BOOL (*bpcallback)(Event *);

class Breakpoint {
protected:
	DWORD64 address;
	int state;
	int size;
	bpcallback action = NULL;
	
public:
	static const int disabled = 0;
	static const int enabled = 1;
	static const int oneshot = 2;
	static const int running = 3;
	
	
	Breakpoint(DWORD64 address) {
		this->address = address;
		state = Breakpoint::disabled;
		size = 1;
	}
	
	Breakpoint(DWORD64 address, int size) {
		this->address = address;
		this->state = Breakpoint::disabled;
		this->size = size;
	}
	
	BOOL is_disabled() {
		if (state == Breakpoint::disabled) 
			return TRUE;
		return FALSE;
	}
	
	BOOL is_enabled() {
		if (state == Breakpoint::enabled)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_one_shot() {
		if (state == Breakpoint::oneshot)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_running() {
		if (state == Breakpoint::running)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_here(DWORD64 address) {
		if (this->address == address) 
			return TRUE;
		return FALSE;
	}
	
	int get_size() {
		return size;
	}
	
	DWORD64 get_address() {
		return address;
	}
	
	DWORD64 get_end_address() {
		return address+size;
	}
	
	int get_state() {
		return state;
	}
	
	void set_action(bpcallback action) {
		this->action = action;
	}
	
	BOOL run_action(Event *ev) {
		if (action == NULL)
			return TRUE;
			
		return action(ev);	//TODO: use try/catch?
	}
	
	void _bad_transition(int state) {
		cout << "bad transition from " << this->state << " to " << state << endl;
	}
	
	void disable() {
		state = Breakpoint::disabled;
	}
	
	void enable() {
		state = Breakpoint::enabled;
	}
	
	void one_shot() {
		state = Breakpoint::oneshot;
	}
	
	void run() {
		state = Breakpoint::running;
	}
	
	void hit(Event *ev) {
		
		//TODO: set the breakpoint on the event, but in a one file mutiple class thats not possible
		
		switch(state) {
			case Breakpoint::enabled:
				run();
				break;
				
			case Breakpoint::running:
				enable();
				break;
				
			case Breakpoint::oneshot:
				disable();
				break;
				
			case Breakpoint::disabled:
				cout << "hit a disabled breakpoint at " << address << endl;
				break;
		}
	}
	
}; // end Breakpoint

class CodeBreakpoint : public Breakpoint {
protected:
	char instruction = '\xcc';
public:
	
	
	
	
	
	
}; //  end CodeBreakpoint



//// Debug //// 


class Debug {
protected:
	int pid;  // debugged pid
	BOOL debugging;
	System *sys;
	Event *last_event = NULL;
	vector<Event *> events;
	Process *process; // debugged process
	BOOL kill_on_exit = TRUE;
	BOOL hostile_mode = FALSE;
	BOOL attached = FALSE;
	BOOL do_trace = FALSE;
	
public:
	Debug() {
		sys = new System();
		debugging = FALSE;
	}
	
	~Debug() {
		delete sys;
	}
	
	int get_pid() {
		return pid;
	}
	
	Process *attach(int pid) {
		if (DebugActiveProcess(pid)) {
			log("attach creating process");
			Process *p = new Process(pid);
			p->scan();
			this->pid = pid;
			this->debugging = TRUE;
			this->process = p;
			return p;
		}
		
		return NULL;
	}
	
	void detach() {
		log("detaching");
		DebugActiveProcessStop(pid);
		
		_cleanup_process();
	}
	
	Process *exec(string file, string cmdline, BOOL debug, BOOL suspended, BOOL console) {
		DWORD ppid;
		BOOL is_admin;
		BOOL inherit_handles = TRUE;
		DWORD flags = 0;
		SECURITY_ATTRIBUTES sec_proc = {0};
		SECURITY_ATTRIBUTES sec_thread = {0};
		STARTUPINFOA startinfo = {0};
		PROCESS_INFORMATION pinfo = {0};
		void *env = NULL;
		string dir = "C:\\";
		
		is_admin = sys->is_admin();
		ppid = GetCurrentProcessId();
		
		flags |= CREATE_DEFAULT_ERROR_MODE;
		flags |= CREATE_BREAKAWAY_FROM_JOB;
		
		if (!console)
			flags |= DETACHED_PROCESS;
		if (suspended)
			flags |= CREATE_SUSPENDED;
		if (debug) {
			flags |= DEBUG_PROCESS;
			flags |= DEBUG_ONLY_THIS_PROCESS;
		}
		
		try {
			if (!CreateProcessA((LPSTR)file.c_str(), (LPSTR)cmdline.c_str(), &sec_proc, &sec_thread, inherit_handles, flags, env, (LPSTR)dir.c_str(), &startinfo, &pinfo)) {
				cout << "cannot create process " << GetLastError() << endl;
				return NULL;
				
			} else  {
				cout << "process created pid:" << pinfo.dwProcessId << endl;
				sys->set_kill_on_exit_mode(TRUE);
				this->kill_on_exit = TRUE;
				this->pid = pinfo.dwProcessId;
				this->debugging = TRUE;
				log("exec try creating process");
				Process *proc = new Process(pinfo.dwProcessId);
				proc->scan();
				this->process = proc;
				return proc;
			}
			
		} catch(...) {
			HANDLE hProcess;
			HANDLE token;
			HANDLE token2;
			SECURITY_IMPERSONATION_LEVEL lvl;
			
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ppid);
			OpenProcessToken(hProcess, 0, &token);
			DuplicateToken(token, lvl, &token2);
			
			CloseHandle(token);
			CloseHandle(hProcess);
			CreateProcessAsUser(token2, file.c_str(), (LPSTR)cmdline.c_str(), &sec_proc, &sec_thread, inherit_handles, flags, env, dir.c_str(), &startinfo, &pinfo);
			sys->set_kill_on_exit_mode(TRUE);
			this->kill_on_exit = TRUE;
			this->pid = pinfo.dwProcessId;
			this->debugging = TRUE;
			log("exec catch creating process");
			Process *proc = new Process(pinfo.dwProcessId);
			proc->scan();
			this->process = proc;
			return proc;
		}
		
		return NULL;
	}
	
	void _cleanup_process() {
		log("_cleanup_process");
		/*if (debugging)
			delete process;*/
		debugging = FALSE;
	}
	
	void kill() {
		log("killing");
		if (process != NULL && process->is_alive()) {
			log("proces alive");
			try {
				log("trying suspend");
				process->suspend();
				log("suspended");
				detach();
				log("detached");
				
				if (kill_on_exit) {
					process->kill();
					log("killed");
				}
					
				
			} catch(...) {
				log("catch");
				
				try {			
					log("killing process");
					process->kill();
					log("process killed");
				} catch(...) {
					cout << "cannot stop the process." << endl;
				}
			}
		}
		
		_cleanup_process();
	}
	
	Event *wait(DWORD millis) {
		DEBUG_EVENT ev;
		WaitForDebugEvent(&ev, millis);
		
		Event *event = new Event(ev, this->process);
		events.push_back(event);
		last_event = event;
		return event;
	}
	
	Event *wait() {
		DEBUG_EVENT ev;
		WaitForDebugEvent(&ev, INFINITE);
		
		Event *event = new Event(ev, this->process);
		events.push_back(event);
		last_event = event;
		return event;
	}
	
	Event *pop_event() {
		Event *ev;
		int last_item;
		
		if (events.size() == 0)
			return NULL;
		
		last_item = events.size()-1;
		ev = events[last_item];
		events.erase(events.begin()+last_item);
		
		return ev;
	}
	
	void dispatch() {
		Event *event;
		
		if (events.size() == 0 && last_event == NULL)
			return;
		
		if (events.size() > 0) {
			

			event = pop_event();
		} else {
			event = last_event;
		}
		
		switch(event->get_event_code()) {
			case EXCEPTION_DEBUG_EVENT:
				switch(event->get_exception_code()) {
					case EXCEPTION_BREAKPOINT:
                    case EXCEPTION_WX86_BREAKPOINT:
                    case EXCEPTION_SINGLE_STEP:
                    case EXCEPTION_GUARD_PAGE:
                    	event->set_continue_status(DBG_CONTINUE);
                    	break;
                    case EXCEPTION_INVALID_HANDLE:
                    	if (hostile_mode)
                    		event->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
                    	break;
                    		event->set_continue_status(DBG_CONTINUE);
                    default:
                    	event->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
				}
				break;
				
			case RIP_EVENT:
				if (event->get_rip_type() == SLE_ERROR)
					event->set_continue_status(DBG_TERMINATE_PROCESS);
				break;
				
			default:
				event->set_continue_status(DBG_CONTINUE);
				break;
				
		}
		
		_dispatch(event);
	}
	
	void _dispatch(Event *event) {
		//TODO: implement
	}
	
	void cont() {
		if (last_event == NULL)			
			return;
		cont(last_event);
	}
		
	void cont(Event *event) {
		
		if (debugging && pid == event->get_pid()) {
			process->flush_instruction_cache();
			ContinueDebugEvent(event->get_pid(), event->get_tid(), event->get_continue_status());
		}
		
		if (event == last_event) {
			last_event = NULL; // why?
		}
	
	}
	
	void resume(){
		process->resume();
	}
	
	void stop() {
		if (last_event != NULL) {
			log("there is last event");
			disable_process_breakpoints(last_event->get_pid());
			disable_thread_breakpoints(last_event->get_tid());
			last_event->set_continue_status(DBG_CONTINUE);
			cont(last_event);
		}
		
		log("cont finished");
		
		if (kill_on_exit)
			kill_all();
		else
			detach();
		
		log("stop process finished");	
	}
	
	void next() {
		try {
			log("waiting");
			wait();
			log("waited");
		} catch(...) {
			log("next catch");
			stop();
			return;
		}
		
		log("dispatching");
		dispatch();
		log("dispatched");
		cont();	
	}
	
	void loop() {
		for (;;) next();
	}
	
	BOOL is_debugee_started() {
		return debugging;
	}
	
	BOOL is_debugee_attached() {
		return attached;
	}
	
	BOOL is_hostile_mode() {
		return hostile_mode;
	}
	
	void set_hostile_mode() {
		hostile_mode = TRUE;
	}
	
	/*
	void interactive() {
		cout << endl;
		cout << string(79, '-') << endl;
		cout << "Interactive debugging session started." << endl;
        cout << "Use the \"help\" command to list all available commands." << endl;
        cout << "Use the \"quit\" command to close this session." << endl;
        cout << string(79, '-') << endl;
        if (last_event == NULL)
        	cout << endl;
        
        auto console = new Console();
        console.confirm_quit(TRUE);
        console.load_history();
        
        console.start_using_debugger(self);
        console.loop();
        
        console.stop_using_debugger();
        console.save_history();
        
        cout << endl;
        cout << string(79, '-') << endl;
        cout << "Interactive debugging session closed." << endl;
        cout << string(79, '-') << endl;
        cout << endl;
	}*/
	
	void _notify_create_process(Event *event) {
		
	}
	
	void disable_process_breakpoints(int pid) {
		
	}
	
	void disable_thread_breakpoints(int tid) {
		
	}
	
	void kill_all() {
		log("killall");
		kill();
	}
	
	void trace() {
		do_trace = !do_trace;
	}
	
	void log(string msg) {
		cout << "=> " << msg << endl;
	}
};

