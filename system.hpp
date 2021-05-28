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

#include "service.hpp"
#include "process.hpp"
#include "window.hpp"

//using namespace std;



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
	
	BOOL adjust_privileges(TOKEN_PRIVILEGES *new_state) {
		HANDLE token;
		
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
			AdjustTokenPrivileges(token, FALSE, new_state, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
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
					
					CloseHandle(scm);
					return;
				}
			
			    if (GetLastError() != ERROR_MORE_DATA) {
			      return;
			    }
			    
			    //TODO: verify buff
			    //buff_sz += more_bytes_needed;
			    //buff = malloc(buff_sz);
			    
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
	
	BOOL has_process(DWORD pid) {
		for (auto process: processes) {
			if (process->get_pid() == pid)
				return TRUE;
		}
		return FALSE;
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
	
	Process *get_process(DWORD pid) {
		for (auto proc : processes) {
			if (proc->get_pid() == pid)
				return proc;
		}
		return NULL;
	}
	
	Thread *get_thread(DWORD tid) {
		for (auto proc : processes) {
			auto t = proc->get_thread(tid);
			return t;
		}
		return NULL;
	}
	
	void __add_process(Process *proc) {
		processes.push_back(proc);
	}
	
	void request_debug_privileges() {
		TOKEN_PRIVILEGES state;
		adjust_privileges(&state);
	}
	
	void load_dbghelp() {
		LoadLibraryA("c:\\windows\\system32\\dbghelp.dll");
	}
	
	void fix_symbol_store_path(string symbol_store_path, bool remote, bool force)  {
		//TODO: implement symbols
	}
	
	void _notify_exit_process(DWORD pid) {
		for (int i=0; i<processes.size(); i++) {
			if (processes[i]->get_pid() == pid) {
				processes.erase(processes.begin()+i);
				return;
			}
		}
	}
	
	void _notify_unload_dll(void *base_addr) {
		for (auto proc : processes) {
			proc->_notify_unload_dll(base_addr);
		}
	}
	
	
}; // end System

