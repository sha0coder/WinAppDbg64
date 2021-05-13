/*
	WinAppDbg64
	@sha0coder
	
	Mario Vilas' WinAppDbg port to C++ 64bits
	
	COMPILER FLAGS:
		 -std=C++11
	
	LINKER FLAGS:
		-lpsapi 
	
   
*/


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

using namespace std;

//// MODULE ////


class Module {
private:
	int pid;
	MODULEENTRY32 me;
	FileHandle *hFile;
	void *base_of_dll;
	Process *proc;
	string filename = "";
	
public:
	Module(int pid, MODULEENTRY32 me) {
		this->pid = pid;
		this->me = me;
	}
	
	Module(void *base_of_dll, FileHandle *hFile, string filename, Process *proc) {
		//TODO: get the module entry
		this->base_of_dll = base_of_dll;
		this->hFile = hFile;
		this->pid = proc->get_pid();
		this->process = proc;
		this->filename = filename;
	}
	
	Module(void *base_of_dll, Process *proc) {
		//TODO: get the module entry
		this->base_of_dll = base_of_dll;
		this->pid = proc->get_pid();
		this->process = proc;
	}
	
	BOOL operator== (Module *m) {
		if (this->get_base() == m->get_base() && this->get_name_string() == m->get_name_string())
			return TRUE;
		return FALSE;
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
	
	string get_name_string() {
		string str(me.szModule);
		return str;
	}
	
	string get_filename() {
		return filename;
	}
	
	HANDLE get_handle() {
		return me.hModule;
	}
	
	FileHandle *get_file_handle() {
		return this->hFile;
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



