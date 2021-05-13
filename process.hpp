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

#include "thread.hpp"
#include "module.hpp"

using namespace std;




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
	
	void __add_module(Module *module) {
		this->modules.push_back(module);
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
	
	vector<DWORD> get_tids() {
		vector<DWORD> tids;
		
		for (auto t : threads) 
			tids.push_back(t->get_tid());
		
		return tids;
	}
	
	vector<Thread *> get_threads() {
		return threads;
	}
	
	Module *get_module_at_address(DWORD64 address) {
		for (auto module : modules) {
			if (module->get_base() == address) {
				return module;
			}
		}
		return NULL;
	}
	
	Thread *get_thread(DWORD tid) {
		for (auto t : threads) {
			if (t->get_tid() == tid) 
				return t;
		}
		return NULL;
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
	
	string get_perms_rwx(void *address) {
		MEMORY_BASIC_INFORMATION mbi;
		BOOL has_content, is_commited;
		
		try {
			mbi = mquery(address);
		} catch(...) {
			return string("---");
		}
		
		is_commited = (mbi.State & MEM_COMMIT);
		has_content = (is_commited && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)));
		
		if (!has_content)
			return string("---");
		
		if (mbi.Protect & PAGE_EXECUTE_READWRITE)
			return string("rwx");
		
		if (mbi.Protect & PAGE_READWRITE) 
			return string("rw-");
			
		return string("r--");
	}
	
	SIZE_T write(void *address, void *buff, SIZE_T size) {
		return poke(address, buff, size);
	}
	
	SIZE_T poke(void *address, void *buff, SIZE_T size) {
		MEMORY_BASIC_INFORMATION mbi;
		HANDLE hndl;
		SIZE_T len;
		DWORD prot = 0;
		BOOL has_content, is_commited;

		try {
			mbi = mquery(address);
		} catch(...) {
			cout << "/!\\ invalid address" << endl;
			return 0;
		}
		
		is_commited = (mbi.State & MEM_COMMIT);
		has_content = (is_commited && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)));
		
		if (!has_content) {
			cout << "cant write, address has not content " << endl;
			return 0;
		}
		
		if (mbi.Type & MEM_IMAGE || mbi.Type & MEM_MAPPED)
			prot |= PAGE_WRITECOPY;
		
		if (mbi.AllocationProtect & PAGE_READWRITE || mbi.AllocationProtect & PAGE_EXECUTE_READWRITE)
			prot = 0;
		
		else if (mbi.AllocationProtect & PAGE_EXECUTE_READ || mbi.AllocationProtect & PAGE_EXECUTE_WRITECOPY)
			prot = PAGE_EXECUTE_READWRITE;
			
		else 
			prot = PAGE_READWRITE;
			
		cout << "prot: " << prot;
			
		if (prot) 
			mprotect(address, size, prot);
		
		hndl = get_handle(PROCESS_VM_WRITE|PROCESS_VM_OPERATION);
		if (!WriteProcessMemory(hndl, address, buff, size, &len))
			cout << "cant write memory of process " << this->pid << " err: " << GetLastError() << endl;
		CloseHandle(hndl);
		
		//TODO: restore previous privileges?
		return len;
	}
	
	SIZE_T read(void *address, void *buff, SIZE_T size) {
		HANDLE hndl;
		SIZE_T len;
		
		hndl = get_handle(PROCESS_VM_READ);
		ReadProcessMemory(hndl, address, buff, size, &len);
		CloseHandle(hndl);
			
		return len;	  // 0 bytes read mean cant read that address, not paged
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
	
	unsigned int read_unsigned_int(void *address) {
		unsigned int value;
		
		read(address, (void *)&value, sizeof(unsigned int));
		
		return value;
	}
	
	void write_unsigned_int(void *address, unsigned int value) {
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
	
	void write_string(void *address, string str) {
		// write the null byte at the end or don't write it?
		char *addr;
		
		addr = (char *)address;
		
		for (auto c: str) { 
			this->write_char(addr, c);
			addr++;	
		}
	}
	
	string read_string(void *address) {
		char *addr = (char *)address;
		char c;
		string str = "";
		
		while (addr < (void *)END_ADDRESS) {
			c = read_char(addr);
			if (c == 0x00) {
				break;
			} else {
				str += c;
			}
			addr ++;
		}
		
		return str;
	}
	//TODO: implement unicode
	
	string read_string_optimized(void *address) {
		//TODO: implement this
		string str = "";
		char *page;
		int nullpos;
		BOOL found;
		
		if (!is_buffer(address, 1)) {
			cout << "Invalid address, cant read a string" << endl;
			return NULL;
		}
		
		for (auto m : get_memory_map(address, 0)) {
			if (m.State == MEM_COMMIT && !(m.Protect & PAGE_GUARD)) {
				page = (char *)malloc(m.RegionSize);
				this->read(m.BaseAddress, page, m.RegionSize);
				for (nullpos=0; nullpos<m.RegionSize; nullpos++) {
					if (page[nullpos] == 0x00) {
						found = TRUE;
						break;
					}				
				}
				
				if (found) {
					str += string(page, nullpos);
					free(page);
					return str;
				}
			
				str += string(page);
				free(page);
				
				return str;
			}
		}
		
		return str;
	}
	
	vector<MEMORY_BASIC_INFORMATION> get_memory_maps() {
		return get_memory_map(0, 0);
		
		//TODO: create map object with getters for struct members.
	}
	
	vector<MEMORY_BASIC_INFORMATION> get_memory_map(void *start_addr, void *end_addr) {
		vector<MEMORY_BASIC_INFORMATION> map;
		vector<DWORD64> range;
		MEMORY_BASIC_INFORMATION mbi;
		DWORD64 prev_addr, curr_addr, min_addr, max_addr;
	
		
		range = MemoryAddresses::align_address_range((DWORD64)start_addr, (DWORD64)end_addr);
		min_addr = range[0];
		max_addr = range[1];
		
		prev_addr = 0;
		curr_addr = min_addr;
		
		cout << curr_addr << " - " << max_addr << endl;
		
		while (curr_addr < max_addr) {
			try {
				mbi = mquery((void *)curr_addr);
			} catch(...) {
				break;
			}
			map.push_back(mbi);
			
			curr_addr = ((DWORD64)mbi.BaseAddress) + mbi.RegionSize;
		}
		
		return map;
	}
	
	BOOL is_buffer(void *address, SIZE_T size) {
		MEMORY_BASIC_INFORMATION mbi;
		BOOL has_content;
		BOOL is_commited;
		char *ptr = (char *)address;
		
		
		if (size <= 0) {
			cout << "is_buffer() bad size" << endl;
			return FALSE;
		}
		
		// TODO: optimize, there is no need to scan all the offsets sice we have the mbi.RegionSize
		
		for (int off=0; off<size; off++) {
		
			try {
				mbi = mquery(ptr + off);
			} catch(...) {
				return FALSE;	
			}
			
			is_commited = (mbi.State & MEM_COMMIT);
			has_content = (is_commited && !(mbi.Protect & (PAGE_GUARD|PAGE_NOACCESS)));
			
			if (!has_content)
				return FALSE;
			
		}
		
		return TRUE;		
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
	
	BOOL has_thread(DWORD tid) {
		for (auto t : threads) {
			if (t->get_tid() == tid)
				return TRUE;
		}
		return FALSE;
	}
	
	void add_thread(Thread *t) {
		threads.push_back(t);
	}
	
	
}; // end Process

