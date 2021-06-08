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


#include <string>
#include <map>
#include <vector>
#include <sstream>

#include "process.hpp"
#include "thread.hpp"
#include "kernel.hpp"
#include "util.hpp"



//// EVENT /////



class Event {
protected:
	Process *process;
	DEBUG_EVENT ev;
	string name;
	DWORD continue_status;
public:
	
	
	Event(DEBUG_EVENT ev) {
		this->ev = ev;
	}
	
	Event(Process *process, DEBUG_EVENT ev) {
		this->process = process;
		this->ev = ev;
	}
	
	string get_name() {
		return name;
	}
	
	Process *get_process() {
		return process;
	}
	
	Module *get_module() {
		return get_process()->get_main_module();
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
	
	/*
	Process *get_process() {
		auto pid = get_pid();
		auto system = debug->system;
		
		if (system->has_process(pid)) {
			auto proc = system->get_process(pid);
			return proc;
		}
		
		auto process = new Process(pid);
		system->__add_process(process);
		process->scan_modules();
		return process;
	}*/
	
	Thread *get_thread() {
		auto tid = get_tid();
		if (process->has_thread(tid)) {
			auto thread = process->get_thread(tid);
			return thread;
		}
		
		auto thread = new Thread(get_pid(), tid);
		process->add_thread(thread);
		return thread;
	}
	/*
	void *get_start_address() {
		//TODO: optimize this, dont use try/catch instead calculate which member has lpStartAddress
		try {
			switch (get_event_code()) {
				case EXCEPTION_DEBUG_EVENT:
					return NULL;
				case CREATE_THREAD_DEBUG_EVENT:
					return (void *)ev.u.CreateThread.lpStartAddress;
	        	case CREATE_PROCESS_DEBUG_EVENT:
					return (void *)ev.u.CreateProcessInfo.lpStartAddress;
	        	case EXIT_THREAD_DEBUG_EVENT:
	        		return (void *)ev.u.ExitThread.lpStartAddress;
	        	case EXIT_PROCESS_DEBUG_EVENT:
	        		return (void *)ev.u.ExitProcess.lpStartAddress;
	        	case LOAD_DLL_DEBUG_EVENT:
	        		return (void *)ev.u.LoadDll.lpStartAddress;
	        	case UNLOAD_DLL_DEBUG_EVENT:
	        		return (void *)ev.u.UnloadDll.lpStartAddress;
	        	case OUTPUT_DEBUG_STRING_EVENT:
	        		return (void *)ev.u.DebugString.lpStartAddress;
	        	case RIP_EVENT:
	        		return (void *)ev.u.RipInfo.lpStartAddress;
			}
		} catch(...) {}
		
		return NULL;
	}*/
	
}; // end Event

//// CreateThreadEvent ////

class CreateThreadEvent : public Event {
public:
	string event_method = "create_thread";
	string event_name = "Thread creation event";
	string event_description = "A new thread has started";
	
	CreateThreadEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	
	ThreadHandle *get_thread_handle() {
		auto hThread = ev.u.CreateThread.hThread;
		if (hThread == 0 ||
			hThread == NULL ||
			hThread == INVALID_HANDLE_VALUE) {
				return NULL;
			}
		
		auto th = new ThreadHandle(hThread, false);
		th->set_access(THREAD_ALL_ACCESS);
		return th;
	}
	
	void *get_teb() {
		return ev.u.CreateThread.lpThreadLocalBase;
	}
	
	void *get_start_address() {
		return (void *)ev.u.CreateThread.lpStartAddress;
	}
	
	
}; // end CreateThreadEvent


class CreateProcessEvent : public Event {
public:
	string event_method = "create_process";
	string event_name = "Process creation event";
	string event_description = "A new process has started";
	
	CreateProcessEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	FileHandle *get_file_handle() {
		auto hFile = ev.u.CreateProcessInfo.hFile;
		if (hFile == 0 || hFile == NULL || hFile == INVALID_HANDLE_VALUE) 
			return NULL;
		
		auto fh = new FileHandle(hFile, true);
		return fh;
	}
	
	ProcessHandle *get_process_handle() {
		auto hProcess = ev.u.CreateProcessInfo.hProcess;
		if (hProcess == 0 || hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) 
			return NULL;
			
		auto ph = new ProcessHandle(hProcess, false);
		ph->set_access(PROCESS_ALL_ACCESS);
		return ph;
	}
	
	ThreadHandle *get_thread_handle() {
		auto hThread = ev.u.CreateProcessInfo.hThread;
		if (hThread == 0 || hThread == NULL || hThread == INVALID_HANDLE_VALUE) 
			return NULL;
		
		auto th = new ThreadHandle(hThread, false);
		th->set_access(THREAD_ALL_ACCESS);
	}
	
	void *get_start_address() {
		return (void *)ev.u.CreateProcessInfo.lpStartAddress;
	}
	
	void *get_image_base() {
		return ev.u.CreateProcessInfo.lpBaseOfImage;
	}
	
	void *get_teb() {
		return ev.u.CreateProcessInfo.lpThreadLocalBase;
	}
	
	string get_debug_info() {
		auto raw = ev.u.CreateProcessInfo;
		void *ptr = (void *)((char *)raw.lpBaseOfImage + raw.dwDebugInfoFileOffset);
		auto sz = raw.nDebugInfoSize;
		
		char *buff = (char *)malloc(sz);
		process->read(ptr, buff, sz);
		
		string str(buff, strlen(buff));
		free(buff);
		return str;
	}
	
	string get_filename() {
		auto hFile = get_file_handle();
		if (hFile != NULL) {
			auto filename = hFile->get_filename(); 
			if (!filename.empty())
				return filename;
		}
		
		auto proc = get_process();
		auto lpRemoteFilenamePtr = ev.u.CreateProcessInfo.lpImageName;
		if (lpRemoteFilenamePtr) {
			auto lpFilename = proc->read_pointer(lpRemoteFilenamePtr);
			bool bUnicode = (ev.u.CreateProcessInfo.fUnicode?true:false);
			auto szFilename = proc->read_string(lpFilename); //TODO: implement unicode
			return szFilename;
		}
		
		string str;
		return str;
	}
	
	void *get_module_base() {
		return get_image_base();
	}
	
}; // end CreateProcessEvent

class ExitThreadEvent : public Event {
public:
	string event_method = "exit_thread";
	string event_name = "Thead termination event";
	string event_description = "A thread has finished executing.";
	
	ExitThreadEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	DWORD get_exit_code() {
		return ev.u.ExitThread.dwExitCode;
	}
		
}; // end ExitThreadEvent


class ExitProcessEvent : public Event {
public:
	string event_method = "exit_process";
	string event_name = "Process termination event";
	string event_description = "A process has finished executing.";
	
	ExitProcessEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	
	DWORD get_exit_code() {
		return ev.u.ExitProcess.dwExitCode;
	}
	
	string get_filename() {
		get_module()->get_filename(); //TODO: implement get_filename on module
	}
	
	void *get_image_base() {
		return get_module_base();
	}
	
	void *get_module_base() {
		return (void *)get_module()->get_base();
	}
	
	
	Module *get_module() {
		return get_process()->get_main_module();
	}
	
}; // end ExitProcessEvent


class LoadDLLEvent : public Event {
protected:
	FileHandle *__hFile;
	
public:
	string event_method = "load_dll";
	string event_name = "Module load event";
	string event_description = "A new DLL library was loaded by the debugee";
	
	LoadDLLEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	void *get_module_base() {
		return ev.u.LoadDll.lpBaseOfDll;
	}
	
	Module *get_module() {
		Module *module = NULL;
		auto lpBaseOfDll = get_module_base();
		auto proc = get_process();
		
		
		if (proc->has_module(lpBaseOfDll)) {
			module = proc->get_module(lpBaseOfDll);
		} else {
			
			HANDLE hndl = get_file_handle();
			auto fh = new FileHandle(hndl, false);
			module = new Module(lpBaseOfDll, fh, get_filename(), proc->get_pid());
			proc->__add_module(module);
		}
		 
		return module;
	}
	
	FileHandle *get_file_handle() {
		auto hFile = ev.u.LoadDll.hFile;
		FileHandle *fh;
		
		if (hFile == 0 || hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
			hFile = NULL;
		} 
		
		fh = new FileHandle(hFile, true);
				
		this->__hFile = fh;
		return fh;
	}
	
	string get_filename() {
		auto proc = get_process();
		auto lpRemoteFilenamePtr = ev.u.LoadDll.lpImageName;
		if (lpRemoteFilenamePtr) {
			auto lpFilename = proc->read_pointer(lpRemoteFilenamePtr);
			auto fUnicode = (ev.u.LoadDll.fUnicode?true:false);
			auto szFilename = proc->read_string(lpFilename);
			
			if (!szFilename.empty())
				return szFilename;
		}
		
		auto fh = new FileHandle(get_file_handle(), false);
		string filename = fh->get_filename();
		
		return 	filename;
	}
	
}; // end LoadDLLEvent


class UnloadDLLEvent : public Event {
public:
	string event_method = "unload_dll";
	string event_name = "Module unload event";
	string event_description = "A DLL library was unloaded by the debugee.";
	
	UnloadDLLEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	void *get_module_base() {
		ev.u.UnloadDll.lpBaseOfDll;
	}
	
	Module *get_module() {
		auto lpBaseOfDll = get_module_base();
		auto proc = get_process();
		if (proc->has_module(lpBaseOfDll)) {
			auto module = proc->get_module(lpBaseOfDll);
			return module;
		}
		
		auto module = new Module(lpBaseOfDll, proc->get_pid());
		proc->__add_module(module);
		
		return module;
	}
	
	HANDLE get_file_handle() {
		//TODO: weird things, is the handle or the FileHandle, there is a duplicated flow
		auto hFile = get_module()->get_handle();
		if (hFile == 0 || hFile == NULL) // || hFile == INVALID_FILE_HANDLE)
			return NULL;
		return hFile;
	}
	
	string get_filename() {
		auto module = get_module();
		auto name = module->get_name_string();
		if (name.empty() == 0) 
			return module->get_filename();
		
		return name;
	}
	
	
}; // end UnloadDLLEvent


class OutputDebugStringEvent : public Event {
public:
	string event_method = "output_string";
	string event_name = "Debug string output event";
	string event_description = "The debugee sent a message to the debugger.";
	
	OutputDebugStringEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	string get_debug_string() {
		auto addr = ev.u.DebugString.lpDebugStringData;
		auto unicode = (ev.u.DebugString.fUnicode?true:false);
		auto sz = ev.u.DebugString.nDebugStringLength;
		
		char *buff = (char *)malloc(sz);
		get_process()->read(addr, buff, sz);
		string str(buff, strlen(buff));
		free(buff);
		return str;
	}
	
	
}; // end OutputDebugStringEvent


class RIPEvent : public Event {
public:
	string event_method = "rip";
	string event_name = "RIP event";
	string event_description = "An error has occurred and the process can not be debugged.";
	
	RIPEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
	DWORD get_rip_error() {
		return ev.u.RipInfo.dwError;
	}
	
	DWORD get_rip_type() {
		return ev.u.RipInfo.dwType;
	}


}; // end RIPEvent



//// ExceptionEvent //// 

class ExceptionEvent : public Event {

public:
	string event_name = "exception event";
	string event_description = "An exception was raised by the debugee";
	
	ExceptionEvent(Process *process, DEBUG_EVENT ev) : Event(process, ev) {
	}
	
    map<DWORD, string> exception_method = {
        {EXCEPTION_ACCESS_VIOLATION          , "access_violation"},
        {EXCEPTION_ARRAY_BOUNDS_EXCEEDED     , "array_bounds_exceeded"},
        {EXCEPTION_BREAKPOINT                , "breakpoint"},
        {EXCEPTION_DATATYPE_MISALIGNMENT     , "datatype_misalignment"},
        {EXCEPTION_FLT_DENORMAL_OPERAND      , "float_denormal_operand"},
        {EXCEPTION_FLT_DIVIDE_BY_ZERO        , "float_divide_by_zero"},
        {EXCEPTION_FLT_INEXACT_RESULT        , "float_inexact_result"},
        {EXCEPTION_FLT_INVALID_OPERATION     , "float_invalid_operation"},
        {EXCEPTION_FLT_OVERFLOW              , "float_overflow"},
        {EXCEPTION_FLT_STACK_CHECK           , "float_stack_check"},
        {EXCEPTION_FLT_UNDERFLOW             , "float_underflow"},
        {EXCEPTION_ILLEGAL_INSTRUCTION       , "illegal_instruction"},
        {EXCEPTION_IN_PAGE_ERROR             , "in_page_error"},
        {EXCEPTION_INT_DIVIDE_BY_ZERO        , "integer_divide_by_zero"},
        {EXCEPTION_INT_OVERFLOW              , "integer_overflow"},
        {EXCEPTION_INVALID_DISPOSITION       , "invalid_disposition"},
        {EXCEPTION_NONCONTINUABLE_EXCEPTION  , "noncontinuable_exception"},
        {EXCEPTION_PRIV_INSTRUCTION          , "privileged_instruction"},
        {EXCEPTION_SINGLE_STEP               , "single_step"},
        {EXCEPTION_STACK_OVERFLOW            , "stack_overflow"},
        {EXCEPTION_GUARD_PAGE                , "guard_page"},
        {EXCEPTION_INVALID_HANDLE            , "invalid_handle"},
        {EXCEPTION_POSSIBLE_DEADLOCK         , "possible_deadlock"},
        {EXCEPTION_WX86_BREAKPOINT           , "wow64_breakpoint"},
        {CONTROL_C_EXIT                      , "control_c_exit"},
        {DBG_CONTROL_C                       , "debug_control_c"},
        {MS_VC_EXCEPTION                     , "ms_vc_exception"},
    };

    map<DWORD, string> exception_name = {
        {EXCEPTION_ACCESS_VIOLATION          , "EXCEPTION_ACCESS_VIOLATION"},
        {EXCEPTION_ARRAY_BOUNDS_EXCEEDED     , "EXCEPTION_ARRAY_BOUNDS_EXCEEDED"},
        {EXCEPTION_BREAKPOINT                , "EXCEPTION_BREAKPOINT"},
        {EXCEPTION_DATATYPE_MISALIGNMENT     , "EXCEPTION_DATATYPE_MISALIGNMENT"},
        {EXCEPTION_FLT_DENORMAL_OPERAND      , "EXCEPTION_FLT_DENORMAL_OPERAND"},
        {EXCEPTION_FLT_DIVIDE_BY_ZERO        , "EXCEPTION_FLT_DIVIDE_BY_ZERO"},
        {EXCEPTION_FLT_INEXACT_RESULT        , "EXCEPTION_FLT_INEXACT_RESULT"},
        {EXCEPTION_FLT_INVALID_OPERATION     , "EXCEPTION_FLT_INVALID_OPERATION"},
        {EXCEPTION_FLT_OVERFLOW              , "EXCEPTION_FLT_OVERFLOW"},
        {EXCEPTION_FLT_STACK_CHECK           , "EXCEPTION_FLT_STACK_CHECK"},
        {EXCEPTION_FLT_UNDERFLOW             , "EXCEPTION_FLT_UNDERFLOW"},
        {EXCEPTION_ILLEGAL_INSTRUCTION       , "EXCEPTION_ILLEGAL_INSTRUCTION"},
        {EXCEPTION_IN_PAGE_ERROR             , "EXCEPTION_IN_PAGE_ERROR"},
        {EXCEPTION_INT_DIVIDE_BY_ZERO        , "EXCEPTION_INT_DIVIDE_BY_ZERO"},
        {EXCEPTION_INT_OVERFLOW              , "EXCEPTION_INT_OVERFLOW"},
        {EXCEPTION_INVALID_DISPOSITION       , "EXCEPTION_INVALID_DISPOSITION"},
        {EXCEPTION_NONCONTINUABLE_EXCEPTION  , "EXCEPTION_NONCONTINUABLE_EXCEPTION"},
        {EXCEPTION_PRIV_INSTRUCTION          , "EXCEPTION_PRIV_INSTRUCTION"},
        {EXCEPTION_SINGLE_STEP               , "EXCEPTION_SINGLE_STEP"},
        {EXCEPTION_STACK_OVERFLOW            , "EXCEPTION_STACK_OVERFLOW"},
        {EXCEPTION_GUARD_PAGE                , "EXCEPTION_GUARD_PAGE"},
        {EXCEPTION_INVALID_HANDLE            , "EXCEPTION_INVALID_HANDLE"},
        {EXCEPTION_POSSIBLE_DEADLOCK         , "EXCEPTION_POSSIBLE_DEADLOCK"},
        {EXCEPTION_WX86_BREAKPOINT           , "EXCEPTION_WX86_BREAKPOINT"},
        {CONTROL_C_EXIT                      , "CONTROL_C_EXIT"},  
        {DBG_CONTROL_C                       , "DBG_CONTROL_C"},
        {MS_VC_EXCEPTION                     , "MS_VC_EXCEPTION"},
    };

    map<DWORD, string> exception_description = {
        {EXCEPTION_ACCESS_VIOLATION          , "Access violation"},
        {EXCEPTION_ARRAY_BOUNDS_EXCEEDED     , "Array bounds exceeded"},
        {EXCEPTION_BREAKPOINT                , "Breakpoint"},
        {EXCEPTION_DATATYPE_MISALIGNMENT     , "Datatype misalignment"},
        {EXCEPTION_FLT_DENORMAL_OPERAND      , "Float denormal operand"},
        {EXCEPTION_FLT_DIVIDE_BY_ZERO        , "Float divide by zero"},
        {EXCEPTION_FLT_INEXACT_RESULT        , "Float inexact result"},
        {EXCEPTION_FLT_INVALID_OPERATION     , "Float invalid operation"},
        {EXCEPTION_FLT_OVERFLOW              , "Float overflow"},
        {EXCEPTION_FLT_STACK_CHECK           , "Float stack check"},
        {EXCEPTION_FLT_UNDERFLOW             , "Float underflow"},
        {EXCEPTION_ILLEGAL_INSTRUCTION       , "Illegal instruction"},
        {EXCEPTION_IN_PAGE_ERROR             , "In-page error"},
        {EXCEPTION_INT_DIVIDE_BY_ZERO        , "Integer divide by zero"},
        {EXCEPTION_INT_OVERFLOW              , "Integer overflow"},
        {EXCEPTION_INVALID_DISPOSITION       , "Invalid disposition"},
        {EXCEPTION_NONCONTINUABLE_EXCEPTION  , "Noncontinuable exception"},
        {EXCEPTION_PRIV_INSTRUCTION          , "Privileged instruction"},
        {EXCEPTION_SINGLE_STEP               , "Single step event"},
        {EXCEPTION_STACK_OVERFLOW            , "Stack limits overflow"},
        {EXCEPTION_GUARD_PAGE                , "Guard page hit"},
        {EXCEPTION_INVALID_HANDLE            , "Invalid handle"},
        {EXCEPTION_POSSIBLE_DEADLOCK         , "Possible deadlock"},
        {EXCEPTION_WX86_BREAKPOINT           , "WOW64 breakpoint"},
        {CONTROL_C_EXIT                      , "Control-C exit"},
        {DBG_CONTROL_C                       , "Debug Control-C"},
        {MS_VC_EXCEPTION                     , "Microsoft Visual C++ exception"},
    };
    
    string get_event_method() {
    	return exception_method[get_exception_code()];
	}
	
	string get_exception_name() {
		return exception_name[get_exception_code()];
	}
	
	string get_exception_description() {
		string description = exception_description[get_exception_code()];
		
		if (!description.empty()) 
			return description;
		
		stringstream ss;	
		ss << "exception code " << get_exception_code();
		return ss.str();
	}
	
	BOOL is_first_chance() {
		return ev.u.Exception.dwFirstChance;
	}
	
	BOOL is_last_chance() {
		return !is_first_chance();
	}
	
	BOOL is_non_continuable() {
		return ev.u.Exception.ExceptionRecord.ExceptionFlags & EXCEPTION_NONCONTINUABLE;
	}
	
	BOOL is_continuable() {
		return !is_non_continuable();
	}
	
	BOOL is_user_defined_exception() {
		return (get_exception_code() & 0x10000000 == 0);
	}
	
	BOOL is_system_defined_exception() {
		return !is_user_defined_exception();
	}
	
	DWORD get_exception_code() {
		return ev.u.Exception.ExceptionRecord.ExceptionCode;
	}
	
	void *get_exception_address() {
		return ev.u.Exception.ExceptionRecord.ExceptionAddress;
	}
	
	long long int get_exception_information(int index) {
		if (index < 0 || index > EXCEPTION_MAXIMUM_PARAMETERS) {
			cout << "get_exception_information() out of range" << endl;
			return 0;
		}
		
		auto info = ev.u.Exception.ExceptionRecord.ExceptionInformation;
		auto value = info[index];
		
		return value;
	}
	
	vector<int> get_exception_information_as_list() {
		vector<int> data;
		
		auto info = ev.u.Exception.ExceptionRecord.ExceptionInformation;
		
		for (int i=0; i<EXCEPTION_MAXIMUM_PARAMETERS; i++) {
			data.push_back(info[i]);
		}
		
		return data;
	}
	
	int get_fault_type() {
		auto code = get_exception_code();
		
		if (code != EXCEPTION_ACCESS_VIOLATION &&
			code != EXCEPTION_IN_PAGE_ERROR &&
			code != EXCEPTION_GUARD_PAGE) {
				cout << "get_full_type() is not meaningful for " << get_exception_name() << endl;
				return 0;
		}
		
		return get_exception_information(0);	
	}
	
	DWORD64 get_fault_address() {
		auto code = get_exception_code();
		
		if (code != EXCEPTION_ACCESS_VIOLATION &&
			code != EXCEPTION_IN_PAGE_ERROR &&
			code != EXCEPTION_GUARD_PAGE) {
				cout << "get_full_type() is not meaningful for " << get_exception_name() << endl;
				return 0;
		}	
		
		return get_exception_information(1);
	}
	
	int get_ntstatus_code() {
		auto code = get_exception_code();
		
		if (code != EXCEPTION_ACCESS_VIOLATION &&
			code != EXCEPTION_IN_PAGE_ERROR &&
			code != EXCEPTION_GUARD_PAGE) {
				cout << "get_full_type() is not meaningful for " << get_exception_name() << endl;
				return 0;
		}	
		
		return get_exception_information(2);
	}
	
	BOOL is_nested() {
		return (ev.u.Exception.ExceptionRecord.ExceptionRecord?TRUE:FALSE); 
	}
	
	vector<EXCEPTION_RECORD *> get_raw_exception_record_list() {
		vector<EXCEPTION_RECORD *> nested;
		
		EXCEPTION_RECORD *record = &ev.u.Exception.ExceptionRecord;
		for (;;) {
			nested.push_back(record);
			
			record = record->ExceptionRecord;
			if (!record)
				break;
		}
		
		return nested;
	}
	
	vector<Event *> get_nested_exceptions() {
		vector<Event *> nested;
		
		nested.push_back(this);
		auto dwDebugEventCode = ev.dwDebugEventCode;
		auto dwProcessId = ev.dwProcessId;
		auto dwThreadId = ev.dwThreadId;
		auto dwFirstChance = ev.u.Exception.dwFirstChance;
		auto record = &ev.u.Exception.ExceptionRecord;
		
		for (;;) {

			//auto raw = new DEBUG_EVENT();
			DEBUG_EVENT raw;
			raw.dwDebugEventCode = dwDebugEventCode;
			raw.dwProcessId = dwProcessId;
			raw.dwThreadId = dwThreadId;
			raw.u.Exception.ExceptionRecord = *record;
			raw.u.Exception.dwFirstChance = dwFirstChance;
			
			Event *event;
			
			switch(dwDebugEventCode) {
				case EXCEPTION_DEBUG_EVENT:
					event = new ExceptionEvent(process, raw);
					break;
				case CREATE_THREAD_DEBUG_EVENT:
					event = new CreateThreadEvent(process, raw);
					break;
				case CREATE_PROCESS_DEBUG_EVENT:
					event = new CreateProcessEvent(process, raw);
					break;
				case EXIT_THREAD_DEBUG_EVENT:
					event = new ExitThreadEvent(process, raw);
					break;
				case EXIT_PROCESS_DEBUG_EVENT:
					event = new ExitProcessEvent(process, raw);
					break;
				case LOAD_DLL_DEBUG_EVENT:
					event = new LoadDLLEvent(process, raw);
					break;
				case UNLOAD_DLL_DEBUG_EVENT:
					event = new UnloadDLLEvent(process, raw);
					break;
				case OUTPUT_DEBUG_STRING_EVENT:
					event = new OutputDebugStringEvent(process, raw);
					break;
				case RIP_EVENT:
					event = new RIPEvent(process, raw);
					break;
			}
			nested.push_back(event); 
			
			record = record->ExceptionRecord;
			if (record == NULL || record == 0) // || !*record)
				break;
		}
		
		return nested;
	}

}; // end ExceptionEvent

typedef bool (*callback)(Event *);

