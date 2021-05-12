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

#include "process.h"


//// EVENT /////

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
	
	Thread *get_thread() {
		auto tid = get_tid();
		auto proc = get_process();
		if (proc->has_thread(tid)) {
			auto thread = proc->get_thread(tid);
			return thread;
		}
		
		auto thread = new Thread(get_pid(), tid);
		proc->add_thread(thread);
		return thread;
	}
}; // end Event

//// CreateThreadEvent ////

class CreateThreadEvent {
public:
	string event_method = "create_thread";
	string event_name = "Thread creation event";
	string event_description = "A new thread has started";
	
	ThreadHandle *get_thread_handle() {
		auto hThread = ev.u.CreateThread.hThread;
		if (hThread == 0 ||
			hThread == NULL ||
			hThread == INVALID_HANDLE_VALUE) {
				return NULL;
			}
		
		return new ThreadHandle(hThread, false, THREAD_ALL_ACCESS);
	}
	
	
}; // end CreateThreadEvent


//// ExceptionEvent //// 

class ExceptionEvent : public Event {

public:
	string event_name = "exception event";
	string event_description = "An exception was raised by the debugee";
	
	
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
	
	int get_exception_information(int index) {
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
	
	vector<ExceptionEvent *> get_nested_exceptions() {
		vector<ExceptionEvent *> nested;
		
		nested.push_back(this);
		auto dwDebugEventCode = ev.dwDebugEventCode;
		auto dwProcessId = ev.dwProcessId;
		auto dwThreadId = ev.dwThreadId;
		auto dwFirstChance = ev.u.Exception.dwFirstChance;
		auto record = &ev.u.Exception.ExceptionRecord;
		
		for (;;) {

			auto raw = new DEBUG_EVENT();
			raw->dwDebugEventCode = dwDebugEventCode;
			raw->dwProcessId = dwProcessId;
			raw->dwThreadId = dwThreadId;
			raw->u.Exception.ExceptionRecord = *record;
			raw->u.Exception.dwFirstChance = dwFirstChance;
			
			Event *event;
			
			switch(dwDebugEventCode) {
				case EXCEPTION_DEBUG_EVENT:
					event = new ExceptionDebugEvent(process, raw);
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
			if (!*record)
				break;
		}
		
		return nested;
	}

}; // end ExceptionEvent


