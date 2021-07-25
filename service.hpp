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




//// Service ////

class Service {
protected:
	ENUM_SERVICE_STATUS_PROCESSA stat;
	
public:
	Service(ENUM_SERVICE_STATUS_PROCESSA stat) {
		this->stat = stat;
	}
	
	ENUM_SERVICE_STATUS_PROCESSA get_stat() {
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
		SERVICE_DESCRIPTIONA sd;
		
		sd.lpDescription = (LPSTR)description.c_str();
		
		scm = open_scm(SC_MANAGER_ALL_ACCESS);
		if (scm) {
			hService = open_service(scm, SERVICE_CHANGE_CONFIG);
			if (hService) {
				
				ChangeServiceConfig2A(hService, SERVICE_CONFIG_DESCRIPTION, &sd);
				
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

