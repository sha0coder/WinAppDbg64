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
#include <winbase.h>

#include <string>
#include <map>
#include <vector>

using namespace std;

class Handle {
protected:
	bool leak_detection = false;
	bool ownership;
	HANDLE value;
	
	
public:
	Handle(HANDLE hndl, bool ownership) {
		this->ownership = ownership;
		this->value = hndl;
	}
	
	~Handle() {
		try {
			close();
		} catch(...) {
		}
	}
	
	HANDLE value() {
		return value;
	}
	
	void close() {
		if (ownership && value && value != INVALID_HANDLE_VALUE) {
			if (leak_detection) 
				cout << "leak, close handle" << endl;
			CloseHandle(value);
		}
	}
	
	bool is_valid() {
		if (value == 0)
			return false;
		if (value == INVALID_HANDLE_VALUE)
			return false;
		return true;
	}
	
	HANDLE dup() {
		HANDLE hndl;
		
		if (!value || value != INVALID_HANDLE_VALUE) {
			cout << "cant duplicate a closed handle" << endl;
			return NULL;
		}
		
		hndl = DuplicateHandle(NULL, value, NULL, NULL, STANDARD_RIGHTS_ALL, FALSE, DUPLICATE_SAME_ACCESS);
		
		if (leak_detection)
			cout << "duplicated handle " << value << " -> " << hndl << endl;
		
		return hndl;
	}
	
	void wait(DWORD millis) {
		if (!is_valid()) {
			cout << "cannot wait a closed handle" << endl;
			return;
		}
		
		WaitForSingleObject(value, millis);
	}
	
	bool __get_inherit() {
		if (!is_valid()) {
			cout << "cannot inherit a closed handle" << endl;
			return false;
		}
		
		if (GetHandleInformation(value, HANDLE_FLAG_INHERIT))
			return true;
		return false;
	}
	
	void __set_inherit(bool inherit) {
		if (!is_valid()) {
			cout << "cannot inherit a closed handle" << endl;
			return;
		}
		
		if (inherit)
			SetHandleInformation(value, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
		else
			SetHandleINformation(value, 0, 0);
	
	}
	
	bool __get_protect_from_close() {
		if (!is_valid()) {
			cout << "cannot protect a closed handle" << endl;
			return false;
		}
		
		if (GetHandleInformation(value, HANDLE_FLAG_PROTECT_FROM_CLOSE))
			return true;
		return false;
	}
	
	void __set_protect_from_close(bool protect) {
		if (!is_valid()) {
			cout << "cannot protect a closed handle" << endl;
			return;
		}
		
		if (protect)
			SetHandleInformation(value, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
		else
			SetHandleInformation(value, 0, 0);
		
	}
	
}; // end Handle

class FileHandle : public Handle {
public:
	string get_filename() {
		
		char *name = malloc(0x1004);
		
		try {
			GetFileInformationByHandleEx(value, FILE_INFO_BY_HANDLE_CLASS.FileNameInfo, name, 0x1004);
			
			string str(name);
			free(name)
			return str;
			
		} catch(...) {
			IO_STATUS_BLOCK io;
			NtQueryInformationFile(value, &io, name, 0x1004, FileNameInformation);
		}
		
		string str(name);
		free(name)
		return str;
	}
	

}; // end FileHandle


class ProcessHandle : public Handle {
protected:
	DWORD access;
	
public:
	void set_access(DWORD access) {
		this->access = access;
	}
	
	DWORD get_pid() {
		return GetProcessId(value);
	}
	
};




class ThreadHandle : public Handle {
protected:
	DWORD access;

public:	
	void set_access(DWORD access) {
		this->access = access;
	}
	
	DWORD get_tid() {
		GetThreadId(value);
	}
		
};
