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
#include <algorithm>

#include "kernel.hpp"
#include "symbol.hpp"
#include "label.hpp"

//// MODULE ////



class Module {
private:
	int pid = 0;
	MODULEENTRY32 me;
	MODULEINFO modinfo;
	FileHandle *hFile = NULL;
	void *base_of_dll = NULL;
	void *entry_point = NULL;
	DWORD size_of_image = 0;
	string filename = "";
	vector<Symbol *> symbols;

	
public:
	Module(int pid, MODULEENTRY32 me) {
		this->pid = pid;
		this->me = me;
	}
	
	Module(void *base_of_dll, FileHandle *hFile, string filename, DWORD pid) {
		//TODO: get the module entry
		this->base_of_dll = base_of_dll;
		this->hFile = hFile;
		this->pid = pid;
		this->filename = filename;
	}
	
	Module(void *base_of_dll, DWORD pid) {
		//TODO: get the module entry
		this->base_of_dll = base_of_dll;
		this->pid = pid;
	}
	
	~Module() {
		unload_symbols();
	}
	
	BOOL operator== (Module *m) {
		if (this->get_base() == m->get_base() && this->get_name_string() == m->get_name_string())
			return TRUE;
		return FALSE;
	}
	
	DWORD get_pid() {
		return pid;
	}
	
	void set_pid(DWORD pid) {
		this->pid = pid;
	}
	
	void *get_base() {
		return me.modBaseAddr;
	}
	
	void set_modinfo(MODULEINFO modinfo) {
		this->entry_point = modinfo.EntryPoint;
		this->size_of_image = modinfo.SizeOfImage;
		this->modinfo = modinfo;
	}
	
	void *get_entry_point() {
		return this->entry_point;
	}
	
	DWORD get_size_of_image() {
		return this->size_of_image;
	}
	
	
	void *get_ptr() {
		return (void *)me.modBaseAddr;
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
	
	void *resolve(string function) {
		HMODULE hLib = NULL;
		FARPROC addr = NULL;
		
		string fname = get_filename();
		if (fname.empty())
			return NULL;
		
		hLib = GetModuleHandle(fname.c_str());
		if (hLib != NULL)
			addr = GetProcAddress(hLib, function.c_str());
		if (addr == NULL) {
			hLib = LoadLibraryEx(fname.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
			if (hLib != NULL) {
				addr = GetProcAddress(hLib, function.c_str());
				FreeLibrary(hLib);
			}	
		}
		
		return (void *)((char *)addr - (char *)hLib + (char *)this->base_of_dll);
	}
	
	string get_filename() {
		return filename;
	}
	
	void set_filename(string filename) {
		this->filename = filename;
	}
	
	HANDLE get_handle() {
		return me.hModule;
	}
	
	FileHandle *get_file_handle() {
		return this->hFile;
	}
	
	void set_file_handle(FileHandle *hFile) {
		this->hFile = hFile;
	}
	
	DWORD64 load_symbols(HANDLE hProcess, char *pdb_filename) {
		DWORD64 sym_base;
		
		sym_base = SymLoadModuleEx(hProcess, me.hModule, pdb_filename, get_name(),  (DWORD64)get_base(), get_size(), NULL, 0);
		return sym_base;
	}
	
	BOOL is_address_here(void *address) {
		void *base = get_base();
		if (address >= base && address < (char *)base + get_size())
			return TRUE;
		return FALSE;
	}
	
	bool match_name(string name) {
		auto myname = get_name_string();
		transform(name.begin(), name.end(), name.begin(), ::tolower);
		transform(myname.begin(), myname.end(), myname.begin(), ::tolower);
		
		if (name == myname) 
			return true;
		
		return false;
	}
	
	void *resolve_symbol(string function) {
		return NULL; //TODO: implement symbols
	}
	
	string get_label_at_address(void *addr, DWORD offset) {
		DWORD new_offset;
		string function;
		auto start = get_entry_point();
		char *address = (char *)addr;
		
		address += offset;
		offset = address - (char *)get_base();
		
		if (start > 0 && start < address) {
			function = "start";
			offset = address - (char *)start;
		}
		
		Symbol *sym = get_symbol_at_address(address);
		if (sym != NULL) {
			new_offset = address - (char *)sym->address;
			if (new_offset <= offset) {
				function = sym->name;
				offset = new_offset;
			}
		}
		
		return Label::parse_label(get_name(), function, offset);
	}
	
	Symbol *get_symbol_at_address(void *address) {
		vector<Symbol *> syms = get_symbols();
		vector<Symbol *> syms_sorted = sort_symbols(syms);
		
		for (auto sym : syms_sorted) {
			if (sym->address > address)
				return sym;
		}
		
		return NULL;
	}
	
	vector<Symbol *> sort_symbols(vector<Symbol *> syms) {
		//TODO: sort;
		return syms;
	}
	
	vector<Symbol *> get_symbols() {
		return symbols;
	}
	
	void unload_symbols() {
		for (auto sym : symbols)
			delete sym;
		symbols.clear();
	}
	
	void load_symbols(HANDLE hProc) {
		DWORD sym_options;
		BOOL success;
		
		symbols.clear();
		
		// need a handle PROCESS_QUERY_INFORMATION and call from process;
		SymInitialize(hProc, NULL, FALSE);
		sym_options = SymGetOptions();
		
		sym_options |= (
                SYMOPT_ALLOW_ZERO_ADDRESS     |
                SYMOPT_CASE_INSENSITIVE       |
                SYMOPT_FAVOR_COMPRESSED       |
                SYMOPT_INCLUDE_32BIT_MODULES  |
                SYMOPT_UNDNAME
            );
        sym_options &= ~(
                SYMOPT_LOAD_LINES         |
                SYMOPT_NO_IMAGE_SEARCH    |
                SYMOPT_NO_CPP             |
                SYMOPT_IGNORE_NT_SYMPATH
            );
            
        SymSetOptions(sym_options);
        
        SymSetOptions(sym_options | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS); // this can crash? use try/catch
        
        success = SymLoadModule64(hProc, hFile, NULL, NULL, (DWORD64)get_base(), get_size());
        if (!success) 
        	success = SymLoadModule64(hProc, NULL, (char *)get_filename().c_str(), NULL, (DWORD64)get_base(), get_size());
		
		if (success) {
			SymEnumerateSymbols64(hProc, (DWORD64)get_base(), Module::sym_enum_callback, this);
		}
        
		SymCleanup(hProc);
	}
	
	static BOOL sym_enum_callback(PCSTR name, DWORD64 address, ULONG size, PVOID mod) {
		Module *mod2 = (Module *)mod;
		auto sym = new Symbol(name, (void *)address, size);
		mod2->symbols.push_back(sym);
	}
	
};







