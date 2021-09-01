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


	OBJECTS:                                      +----> PageBreakpoint
	                                              |
			  +--> breakpoints --> Breakpoint ----+----> CodeBreakpoint	  
              |                                   |
	         Debug --> events --> Event           +----> HardwareBreakpoint
	          |
System --->	Process -> threads --> Thread
   |	         |
   |             +--> modules --> Module
   |             \
   |              +--> MemoryAddresses
   |
   +---> services --> Service
   |
   +---> Windows
   
   
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

#include "event.hpp"
#include "breakpoint.hpp"
#include "system.hpp"
#include "process.hpp"
#include "util.hpp"
#include "hook.hpp"


//// Debug //// 


class Debug  {
protected:
	int pid;  // debugged pid
	BOOL debugging;
	Event *last_event = NULL;
	vector<Event *> events;
	Process *process; // debugged process
	BOOL kill_on_exit = TRUE;
	BOOL hostile_mode = FALSE;
	BOOL attached = FALSE;
	BOOL do_trace = FALSE;
	vector<DWORD> break_on_ep;

	
	// Breakpoint types
    int BP_TYPE_ANY             = 0;     // to get all breakpoints
    int BP_TYPE_CODE            = 1;
    int BP_TYPE_PAGE            = 2;
    int BP_TYPE_HARDWARE        = 3;

    // Breakpoint states
    int BP_STATE_DISABLED       = Breakpoint::DISABLED;
    int BP_STATE_ENABLED        = Breakpoint::ENABLED;
    int BP_STATE_ONESHOT        = Breakpoint::ONESHOT;
    int BP_STATE_RUNNING        = Breakpoint::RUNNING;

    // Memory breakpoint trigger flags
    int BP_BREAK_ON_EXECUTION   = DebugRegister::BREAK_ON_EXECUTION;
    int BP_BREAK_ON_WRITE       = DebugRegister::BREAK_ON_WRITE;
	int BP_BREAK_ON_ACCESS      = DebugRegister::BREAK_ON_ACCESS;

    // Memory breakpoint size flags
    int BP_WATCH_BYTE           = DebugRegister::WATCH_BYTE;
    int BP_WATCH_WORD           = DebugRegister::WATCH_WORD;
    int BP_WATCH_QWORD          = DebugRegister::WATCH_QWORD;
    int BP_WATCH_DWORD          = DebugRegister::WATCH_DWORD;
    

	bool _debug_static_init = false;

public:
	System* sys;


	Debug() {
		sys = new System();
		debugging = FALSE;
	}
	
	Debug(EventHandler *evh) {		
		this->eh = evh;
		sys = new System();
		debugging = FALSE;
				
		if (!_debug_static_init) {
			_debug_static_init = true;
			sys->request_debug_privileges();
			sys->load_dbghelp();
			sys->fix_symbol_store_path("", false, false);
		}
	}
	
	~Debug() {
		delete sys;
	}
	
	int get_pid() {
		return pid;
	}
	
	void set_hostile_mode() {
		hostile_mode = true;
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
	
	Process *exec(string file) {
		return this->exec(file, "", TRUE, FALSE, TRUE);
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
				cout << "objeto proc pid: " << proc->get_pid() << endl;
				return proc;
			}
			
		} catch(...) {
			HANDLE hProcess;
			HANDLE token;
			HANDLE token2;
			SECURITY_IMPERSONATION_LEVEL lvl;
			
			hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ppid);
			OpenProcessToken(hProcess, 0, &token);
			DuplicateToken(token, SecurityImpersonation, &token2);
			
			CloseHandle(token);
			CloseHandle(hProcess);
			CreateProcessAsUserA(token2, (LPCSTR)file.c_str(), (LPSTR)cmdline.c_str(), &sec_proc, &sec_thread, inherit_handles, flags, env, dir.c_str(), &startinfo, &pinfo);
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

	Process *get_process() {
		return process;
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
		
		Event *event = new Event(this->process, ev, this); //TODO: use event factory?
		events.push_back(event);
		last_event = event;
		return event;
	}
	
	Event *wait() {
		DEBUG_EVENT ev;
		WaitForDebugEvent(&ev, INFINITE);
		
		Event *event = new Event(this->process, ev, this);
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
		
		event->print();
		
		switch(event->get_event_code()) {
			case EXCEPTION_DEBUG_EVENT:
				cout << "is an exception " << endl;
				switch(event->get_exception_code()) {
					case EXCEPTION_BREAKPOINT:
                    case EXCEPTION_WX86_BREAKPOINT:
                    case EXCEPTION_SINGLE_STEP:
                    case EXCEPTION_GUARD_PAGE:
                    	cout << "ex type 1" << endl;
                    	event->set_continue_status(DBG_CONTINUE);
                    	break;
                    case EXCEPTION_INVALID_HANDLE:
                    	cout << "ex type 2" << endl;
                    	if (hostile_mode)
                    		event->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
                    	break;
                    		event->set_continue_status(DBG_CONTINUE);
                    default:
                    	cout << "ex other type" << endl;
                    	event->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
				}
				break;
				
			case RIP_EVENT:
				cout << "rip evet" << endl;
				if (event->get_rip_type() == SLE_ERROR)
					event->set_continue_status(DBG_TERMINATE_PROCESS);
				break;
				
			default:
				cout << "other event lets continue" << endl;
				event->set_continue_status(DBG_CONTINUE);
				break;
				
		}
		
		EventDispatcher_dispatch(event);
	}

	
	void cont() {
		if (last_event == NULL)			
			return;
		cont(last_event);
	}
		
	void cont(Event *event) {
		
		if (debugging && pid == event->get_pid()) {
			cout << "cont 1" << endl;
			process->flush_instruction_cache();
			cout << "cont 2" << endl;
			ContinueDebugEvent(event->get_pid(), event->get_tid(), event->get_continue_status());
			cout << "cont 3" << endl;
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

	
	BOOL in_hostile_code() {
		return hostile_mode;
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
	
	static bool _notify_create_process(Event *event) {
		//TODO: implement
		return true;
	}
	
	static bool disable_process_breakpoints(int pid) {
		//TODO: implement
		return true;
	}
	
	static bool disable_thread_breakpoints(int tid) {
		//TODO: implement
		return true;
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
	
	//// bp cointainer ////

//protected:
    Box<CodeBreakpoint *> code_bp;
    Box<PageBreakpoint *> page_bp;
    Box<HardwareBreakpoint *> hardware_bp;
    Box<Breakpoint *> running_bp;
    vector<DWORD> tracing;
    Box<Breakpoint *> deferred_bp;
    
	
    void __del_running_bp_from_all_threads(Breakpoint *bp) {
    	for (auto tid : running_bp.get_keys()) {
    		if (running_bp.contains(tid, bp)) {
    			running_bp.erase(tid, bp);
    			sys->get_thread(tid)->clear_flags_trap();
			}
		}
	}
    
	void __cleanup_breakpoint(Event *ev, Breakpoint *bp) {
		bp->disable();
		bp->set_action(NULL);
	}
	
	void __cleanup_thread(Event *ev) {
		auto tid = ev->get_tid();
		
		running_bp.erase(tid);
		hardware_bp.erase(tid);
		
		BOOL found = FALSE;
		
		for (int i=0; i<tracing.size(); i++) {
			if (tracing[i] == tid) {
				tracing.erase(tracing.begin()+i);
				break;
			}
		}
	}
	
	void __cleanup_process(Event *ev) {
		auto pid = ev->get_pid();
		
		code_bp.erase(pid);
		page_bp.erase(pid);
		
		deferred_bp.erase(pid);		
	}
	
	void __cleanup_module(Event *ev, Module *module) {
		auto pid = ev->get_pid();
		auto process = ev->get_process();
		//auto module = ev->get_module();
		
		// cleanup thread breakpoints on this module
		for (auto tid : process->get_tids()) {
			
			// running breakpoints
			if (running_bp.contains(tid)) {
				for (auto bp : running_bp.get_items(tid)) {
					void *addr = (void *)bp->get_address();
					
					if (process->get_module_at_address(addr) == module) {
						__cleanup_breakpoint(ev, bp);
						running_bp.erase(tid, bp);
					}
					
				}
			}
			
			// hardware breakpoints
			if (hardware_bp.contains(tid)) {
				for (auto bp : hardware_bp.get_items(tid)) {
					auto addr = bp->get_address();
					
					if (process->get_module_at_address(addr) == module) {
						__cleanup_breakpoint(ev, bp);
						hardware_bp.erase(tid, bp);
					}
				}
			}
		}
		
		// cleanup code breakpoints on this module
		for (auto bp_pid: code_bp.get_keys()) {
			if (bp_pid == pid) {
				
				for (auto bp: code_bp.get_items(pid)) {
					auto addr = bp->get_address();
					
					if (process->get_module_at_address(addr) == module) {
						code_bp.erase(pid, bp);
					}
				}
			}
		}
		
		// cleanup page breakpoints on this module
		for (auto bp_pid: page_bp.get_keys()) {
			if (bp_pid == pid) {
				
				for (auto bp: page_bp.get_items(pid)) {
					auto addr = bp->get_address();
					
					if (process->get_module_at_address(addr) == module) 
						page_bp.erase(pid, bp);
				}
			}
		}
	}
	
	

public:
	
	CodeBreakpoint *define_code_breakpoint(int pid, void *address, BOOL condition, bpcallback action) {
		CodeBreakpoint *bp = new CodeBreakpoint(address, condition, action);
		bp->set_pid(pid);
		
		if (code_bp.contains(pid, bp)) {
			cout << "already exists the code breakpoint " << endl;
			delete bp;
			return NULL;
		}
		
		code_bp.insert(pid, bp);
		
		return bp;
	}

	CodeBreakpoint* define_code_breakpoint_hook(int pid, void* address, BOOL condition, Hook *action) {
		CodeBreakpoint* bp = new CodeBreakpoint(address, condition, action);
		bp->set_pid(pid);

		if (code_bp.contains(pid, bp)) {
			cout << "already exists the code breakpoint " << endl;
			delete bp;
			return NULL;
		}

		code_bp.insert(pid, bp);

		return bp;
	}


	
	PageBreakpoint *define_page_breakpoint(int pid, void *address, int pages, BOOL condition, bpcallback action) {
		PageBreakpoint *bp = new PageBreakpoint(address, pages, condition, action);
		bp->set_pid(pid);
		
		if (page_bp.contains(pid, bp)) {
			cout << "already exists page breakpoint" << endl;
			delete bp;
			return NULL;
		}
		
		page_bp.insert(pid, bp);
		
		return bp;
	}
	
	HardwareBreakpoint *define_hardware_breakpoint(DWORD tid, void *address, int trigger_flag, int size_flag, BOOL condition, bpcallback action) {
		HardwareBreakpoint *bp = new HardwareBreakpoint(address, condition, action);
		bp->config(trigger_flag, size_flag);
		bp->set_tid(tid);
		bp->set_pid(sys->get_thread(tid)->get_pid());
		
		auto begin = bp->get_address();
		auto end = (void *)((char *)begin + bp->get_size());
		
		if (hardware_bp.contains(tid)) {
			for (auto old_bp : hardware_bp.get_items(tid)) {
				auto old_begin = old_bp->get_address();
				auto old_end = (void *)((char *)old_begin + old_bp->get_size());
				if (MemoryAddresses::do_ranges_intersect((DWORD64)begin, (DWORD64)end, (DWORD64)old_begin, (DWORD64)old_end)) {
					cout << "already exists hardware breakpoint" << endl;
					return NULL;
				}
			}
		} else {
			hardware_bp.insert(tid, bp);
		}
		
		return bp;
	}
	
	BOOL has_code_breakpoint(DWORD pid, void *address) {
		return code_bp.contains(pid, address);
	}
	
	BOOL has_page_breakpoint(DWORD pid, void *address) {
		return page_bp.contains(pid, address);
	}
	
	BOOL has_hardware_breakpoint(DWORD tid, void *address) {
		return hardware_bp.contains(tid, address);
	}
	
	CodeBreakpoint *get_code_breakpoint(DWORD pid, void *address) {
		if (!code_bp.contains(pid, address)) {
			cout << "no breakpoint at process " << pid << ", address: " << address << endl;
			return NULL;
		}
		
		return code_bp.get_item_by_address(pid, address);
	}
	
	PageBreakpoint *get_page_breakpoint(DWORD pid, void *address) {
		if (!page_bp.contains(pid, address)) {
			cout << "no breakpoint at process " << pid << ", address: " << address << endl;
			return NULL;
		}
		
		return page_bp.get_item_by_address(pid, address);
	}
	
	HardwareBreakpoint *get_hardware_breakpoint(DWORD tid, void *address) {
		if (!hardware_bp.contains(tid, address)) {
			cout << "no hw breakpoint at thread " << tid << ", address: " << address << endl;
			return NULL;
		}
		
		return hardware_bp.get_item_by_address(pid, address);
	}
	
	void enable_code_breakpoint(DWORD pid, void *address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_code_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_enable(proc);
	}
	
	void enable_page_breakpoint(DWORD pid, void *address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_page_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_enable(proc);
	}
	
	void enable_hardware_breakpoint(DWORD tid, void *address) {
		auto t = this->sys->get_thread(tid);
		auto bp = get_hardware_breakpoint(tid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_enable(t);
	}
	
	void enable_one_shot_code_breakpoint(DWORD pid, void *address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_code_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_one_shot(proc);
	}
	
	void enable_one_shot_page_breakpoint(DWORD pid, void *address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_page_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_one_shot(proc);
	}
	
	void enable_one_shot_hardware_breakpoint(DWORD tid, void *address) {
		auto t = this->sys->get_thread(pid);
		auto bp = get_hardware_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_one_shot(t);
	}
	
	void disable_code_breakpoint(DWORD pid, void *address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_code_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_disable(proc);
	}
	
	void disable_page_breakpoint(DWORD pid, void *address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_page_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_disable(proc);
	}
	
	void disable_hardware_breakpoint(DWORD tid, void *address) {
		auto t = this->sys->get_thread(tid);
		auto bp = get_hardware_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_disable(t);
	}
	
	void erase_code_breakpoint(DWORD pid, void *address) {
		auto bp = get_code_breakpoint(pid, address);
		if (!bp->is_disabled()) 
			disable_code_breakpoint(pid, address);
			
		code_bp.erase(pid, bp);
	}
	
	void erase_page_breakpoint(DWORD pid, void *address) {
		auto bp = get_page_breakpoint(pid, address);
		if (!bp->is_disabled())
			disable_page_breakpoint(pid, address);
		
		page_bp.erase(pid, bp);
	}
	
	void erase_hardware_breakpoint(DWORD tid, void *address) {
		auto bp = get_hardware_breakpoint(tid, address);
		if (!bp->is_disabled())
			disable_hardware_breakpoint(tid, address);
			
		hardware_bp.erase(tid, bp);
	}
	
	vector<Breakpoint *> get_all_breakpoints() {
		vector<Breakpoint *> bp_list;
		
		for (auto pid : code_bp.get_keys()) {
			for (auto bp : code_bp.get_items(pid)) {
				bp_list.push_back(bp);
			}
		}
		
		for (auto pid : page_bp.get_keys()) {
			for (auto bp : page_bp.get_items(pid)) {
				bp_list.push_back(bp);
			}
		}
	
		for (auto tid : hardware_bp.get_keys()) {
			for (auto bp : hardware_bp.get_items(tid)) {
				bp_list.push_back(bp);
			}
		}
	
		return bp_list;	
	}
	
	vector<Breakpoint *> get_process_breakpoints(DWORD pid) {
		vector<Breakpoint *> bp_list;
		

		for (auto bp : code_bp.get_items(pid)) {
			bp_list.push_back(bp);
		}

		for (auto bp : page_bp.get_items(pid)) {
			bp_list.push_back(bp);
		}

		for (auto tid : hardware_bp.get_keys()) {
			for (auto bp : page_bp.get_items(tid)) {
				if (bp->get_pid() == pid)
					bp_list.push_back(bp);
			}
		}
		
		return bp_list;
	}
	
	vector<Breakpoint *> get_process_code_breakpoints(DWORD pid) {
		vector<Breakpoint *> bp_list;
		
		for (auto bp : code_bp.get_items(pid)) {
			bp_list.push_back(bp);
		}
		
		return bp_list;
	}
	
	vector<Breakpoint *> get_process_page_breakpoints(DWORD pid) {
		vector<Breakpoint *> bp_list;
		
		for (auto bp : page_bp.get_items(pid)) {
			bp_list.push_back(bp);
		}
		
		return bp_list;
	}
	
	vector<Breakpoint *> get_thread_hardware_breakpoints(DWORD tid) {
		vector<Breakpoint *> bp_list;
		
		for (auto bp : hardware_bp.get_items(tid)) {
			bp_list.push_back(bp);
		}
		
		return bp_list;
	}
	
	vector<Breakpoint *> get_process_hardware_breakpoints(DWORD pid) {
		vector<Breakpoint *> bp_list;
		
		for (auto tid : hardware_bp.get_keys()) {
			for (auto bp : hardware_bp.get_items(tid)) {
				if (bp->get_pid() == pid)
					bp_list.push_back(bp);
			}
		}
		
		return bp_list;
	}
	
	void enable_all_breakpoints() {
		
		for (auto pid : code_bp.get_keys()) {
			for (auto bp : code_bp.get_items(pid)) {
				if (bp->is_disabled())
					enable_code_breakpoint(pid, bp->get_address());
			}
		}

		for (auto pid : page_bp.get_keys()) {
			for (auto bp : page_bp.get_items(pid)) {
				if (bp->is_disabled())
					enable_page_breakpoint(pid, bp->get_address());
			}
		}

		for (auto tid : hardware_bp.get_keys()) {
			for (auto bp : hardware_bp.get_items(tid)) {
				if (bp->is_disabled())	
					enable_hardware_breakpoint(tid, bp->get_address());
			}
		}
	}
	
	void enable_one_shot_all_breakpoints() {
		
		for (auto pid : code_bp.get_keys()) {
			for (auto bp : code_bp.get_items(pid)) {
				if (bp->is_disabled())
					enable_one_shot_code_breakpoint(pid, bp->get_address());
			}
		}

		for (auto pid : page_bp.get_keys()) {
			for (auto bp : page_bp.get_items(pid)) {
				if (bp->is_disabled())
					enable_one_shot_page_breakpoint(pid, bp->get_address());
			}
		}

		for (auto tid : hardware_bp.get_keys()) {
			for (auto bp : hardware_bp.get_items(tid)) {
				if (bp->is_disabled())	
					enable_one_shot_hardware_breakpoint(tid, bp->get_address());
			}
		}
	}
	
	
	void disable_all_breakpoints() {
		
		for (auto pid : code_bp.get_keys()) {
			for (auto bp : code_bp.get_items(pid)) {
				disable_code_breakpoint(pid, bp->get_address());
			}
		}

		for (auto pid : page_bp.get_keys()) {
			for (auto bp : page_bp.get_items(pid)) {
				disable_page_breakpoint(pid, bp->get_address());
			}
		}

		for (auto tid : hardware_bp.get_keys()) {
			for (auto bp : hardware_bp.get_items(tid)) {
				disable_hardware_breakpoint(tid, bp->get_address());
			}
		}
	}
	
	void erase_all_breakpoints() {
		for (auto pid : code_bp.get_keys()) 
			for (auto bp : code_bp.get_items(pid))
				erase_code_breakpoint(pid, bp->get_address());
				
		for (auto pid : page_bp.get_keys()) 
			for (auto bp : page_bp.get_items(pid))
				erase_page_breakpoint(pid, bp->get_address());
			
			
		for (auto tid : hardware_bp.get_keys()) 
			for (auto bp : hardware_bp.get_items(tid))
				erase_hardware_breakpoint(tid, bp->get_address());
	}
	
	void enable_proces_breakpoints(DWORD pid) {
		Process *proc;
		
		for (auto pid : code_bp.get_keys()) 
			for (auto bp : code_bp.get_items(pid))
				if (bp->is_disabled())
					enable_code_breakpoint(pid, bp->get_address());
				
		for (auto pid : page_bp.get_keys()) 
			for (auto bp : page_bp.get_items(pid))
				if (bp->is_disabled())
					enable_page_breakpoint(pid, bp->get_address());
		
		
		if (sys->has_process(pid)) {
			proc = sys->get_process(pid);
		} else {
			proc = new Process(pid);
			proc->scan_threads();
		}
		
		for (auto thread : proc->get_threads()) {
			for (auto bp : get_thread_hardware_breakpoints(thread->get_tid())) {
				if (bp->is_disabled())
					enable_hardware_breakpoint(thread->get_tid(), bp->get_address());
			}
		}	
	
	}
	
	void enable_one_shot_process_breakpoints(DWORD pid) {
		Process *proc;
		
		for (auto pid : code_bp.get_keys()) 
			for (auto bp : code_bp.get_items(pid))
				if (bp->is_disabled())
					enable_one_shot_code_breakpoint(pid, bp->get_address());
				
		for (auto pid : page_bp.get_keys()) 
			for (auto bp : page_bp.get_items(pid))
				if (bp->is_disabled())
					enable_one_shot_page_breakpoint(pid, bp->get_address());
		
		
		if (sys->has_process(pid)) {
			proc = sys->get_process(pid);
		} else {
			proc = new Process(pid);
			proc->scan_threads();
		}
		
		for (auto thread : proc->get_threads()) {
			for (auto bp : get_thread_hardware_breakpoints(thread->get_tid())) {
				if (bp->is_disabled())
					enable_one_shot_hardware_breakpoint(thread->get_tid(), bp->get_address());
			}
		}	
	}
	
	void disable_process_breakpoint(DWORD pid) {
		Process *proc;
		
		for (auto pid : code_bp.get_keys()) 
			for (auto bp : code_bp.get_items(pid))
				if (bp->is_disabled())
					disable_code_breakpoint(pid, bp->get_address());
				
		for (auto pid : page_bp.get_keys()) 
			for (auto bp : page_bp.get_items(pid))
				if (bp->is_disabled())
					disable_page_breakpoint(pid, bp->get_address());
		
		if (sys->has_process(pid)) {
			proc = sys->get_process(pid);
		} else {
			proc = new Process(pid);
			proc->scan_threads();
		}
		
		for (auto thread : proc->get_threads()) {
			for (auto bp : get_thread_hardware_breakpoints(thread->get_tid())) {
				if (bp->is_disabled())
					disable_hardware_breakpoint(thread->get_tid(), bp->get_address());
			}
		}
	}
	
	void erase_process_breakpoints(DWORD pid) {
		Process *proc;
		
		disable_process_breakpoints(pid);
		
		for (auto pid : code_bp.get_keys()) 
			for (auto bp : code_bp.get_items(pid))
				if (bp->is_disabled())
					erase_code_breakpoint(pid, bp->get_address());
				
		for (auto pid : page_bp.get_keys()) 
			for (auto bp : page_bp.get_items(pid))
				if (bp->is_disabled())
					erase_page_breakpoint(pid, bp->get_address());
		
		if (sys->has_process(pid)) {
			proc = sys->get_process(pid);
		} else {
			proc = new Process(pid);
			proc->scan_threads();
		}
		
		for (auto thread : proc->get_threads()) {
			for (auto bp : get_thread_hardware_breakpoints(thread->get_tid())) {
				if (bp->is_disabled())
					erase_hardware_breakpoint(thread->get_tid(), bp->get_address());
			}
		}
	}
	
	
	// internal handlers of debug events
	
	bool _notify_guard_page(ExceptionEvent *ev) {
		auto address = ev->get_fault_address();
		auto pid = ev->get_pid();
		bool call_handler = TRUE;
		bool condition;
		
		auto mask = ~(MemoryAddresses::page_size() - 1);
		address &= mask;
		
		
		for (auto bp : page_bp.get_items(pid)) {
			auto begin = bp->get_address();
			auto end = (void *)((char *)begin + bp->get_size());
			
			if ((DWORD64)address >= (DWORD64)begin && (DWORD64)address <= (DWORD64)end)	 {
				
				if (bp->is_enabled() || bp->is_one_shot()) {
					ev->set_continue_status(DBG_CONTINUE);
					bp->hit(ev);
					
					if (bp->is_running()) {
						auto tid = ev->get_tid();
						running_bp.insert(tid, bp);
					}
					
					
					
					condition = bp->eval_condition(ev);
					
					if (condition && bp->is_automatic()) {
						bp->run_action(ev);
						call_handler = FALSE;
					} else {
						call_handler = condition;
					}	
				}
				
				
				return call_handler;
			}
		}
		
		ev->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
		return call_handler;
	}
	
	bool _notify_breakpoint(ExceptionEvent *ev) {
		auto address = (void *)ev->get_exception_address();
		auto pid = ev->get_pid();
		bool call_handler = true;
		bool condition;
		
		auto bp = code_bp.get_item_by_address(pid, address);
		if (bp != NULL) {
			if (!bp->is_disabled()) {
				auto thread = ev->get_thread();
				thread->set_pc(address);
				ev->set_continue_status(DBG_CONTINUE);
				bp->hit(ev);
				
				if (bp->is_running()) 
					running_bp.insert(ev->get_tid(), bp);
				
				condition = bp->eval_condition(ev);
				
				// if the breakpoint is automatic, run the action.
				// if not, notify the user.
				
				if (condition && bp->is_automatic()) 
					call_handler = bp->run_action(ev);
				else
					call_handler = condition;
					
			}
		} else if (ev->get_process()->is_system_defined_breakpoint(address)) {
			ev->set_continue_status(DBG_CONTINUE);
			
		} else {
			
			if (is_hostile_mode()) 
				ev->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
			else
				ev->set_continue_status(DBG_CONTINUE);
			
		}
		
		return call_handler;
	}
	
	
	/// EventDispatcher ////	

protected:

	map<DWORD, string> post_exception_notify_callback = {};
	
	EventHandler *eh = NULL;
	
	vector<DWORD> __tracing; // tracing tids
	
public:
	void pre_event_notify_callback(DWORD type, Event *ev) {
		switch(type) {
			case CREATE_THREAD_DEBUG_EVENT:
				cout << "create thread event" << endl;
				_notify_exit_thread(ev);
				break;

			case CREATE_PROCESS_DEBUG_EVENT:
				cout << "create process debug" << endl;
				_notify_create_process(ev);
				break;
				
			case LOAD_DLL_DEBUG_EVENT:
				cout << "load dll event" << endl;
				_notify_load_dll(ev);
				break;
		}
	}
	
	void post_event_notify_callback(DWORD type, Event *ev) {
		switch(type) {
			case EXIT_THREAD_DEBUG_EVENT:
				_notify_exit_thread(ev);
				break;
				
			case EXIT_PROCESS_DEBUG_EVENT:
				_notify_exit_process(ev);
				break;
				
			case UNLOAD_DLL_DEBUG_EVENT:
				_notify_unload_dll(ev);
				break;
				
			case RIP_EVENT:
				_notify_rip(ev);
				break;
		}
	}
	
	void pre_exception_notify_callback(DWORD type, ExceptionEvent *ev) {
			//TODO: is Event or ExceptionEvent??
			
		switch(type) {
			case EXCEPTION_BREAKPOINT:
				_notify_breakpoint(ev);
				break;
		
			case EXCEPTION_WX86_BREAKPOINT:
				_notify_breakpoint(ev);
				break;
		
			case EXCEPTION_SINGLE_STEP:
				_notify_single_step(ev);
				break;

			case EXCEPTION_GUARD_PAGE:
				_notify_guard_page(ev);
				break;

			case DBG_CONTROL_C:
				_notify_debug_control_c(ev);
				break;

			case MS_VC_EXCEPTION:
				_notify_ms_vc_exception(ev);
				break;
		}
		
	}
	
	
	void _notify_exit_thread(Event *ev) {
		//TODO: remove breakpoints?
		process->_notify_exit_thread(ev->get_tid());
	}
	
	void _notify_exit_process(Event *ev) {
		//TODO: remove breakpoints?
		sys->_notify_exit_process(ev->get_pid());
	}
	
	void _notify_unload_dll(Event *ev) {
		//TODO: remove breakpoints?
		ev->get_process()->_notify_unload_dll(ev);
	}
	
	void _notify_rip(Event *ev) {
		detach();
	}
	
	bool _notify_single_step(ExceptionEvent *ev) {
		auto tid = ev->get_tid();
		auto hThread = sys->get_thread(tid);
		auto hProc = ev->get_process();
		bool bCallHandler = true;
		bool bIsOurs = false;
		

		if (is_hostile_mode()) 
			ev->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
		
		bool bFakeSingleStep = false;
		bool bLastIsPushFlags = false;
		bool bNextIsPopFlags = false;
		
		if (is_hostile_mode()) {
			char *pc = (char *)hThread->get_pc();
			char c = hProc->read_char(pc-1);
			if (c == 0xf1)
				bFakeSingleStep = true;
			else if (c == 0x9c)
				bLastIsPushFlags = true;
			c = hProc->read_char(pc);
			if (c == 0x66)
				c = hProc->read_char(pc+1);
			if (c == 0x9d) {
				if (bLastIsPushFlags) 
					bLastIsPushFlags = false;
				else
					bNextIsPopFlags = true;				
			}
		}
		
		if (is_tracing(tid)) {
			bIsOurs = true;
			if (!bFakeSingleStep)
				ev->set_continue_status(DBG_CONTINUE);
			hThread->set_tf();
			
			if (bLastIsPushFlags || bNextIsPopFlags) {
				auto sp = hThread->get_sp();
				auto flags = hProc->read_unsigned_int((void *)sp);
				if (bLastIsPushFlags)
					flags &= ~trap;
				else
					flags |= trap;
				hProc->write_unsigned_int((void *)sp, flags);
			}
		}
		
		try {
			auto running = running_bp.get_items(tid);
		
			bIsOurs = true;
			if (!bFakeSingleStep)
				ev->set_continue_status(DBG_CONTINUE);
			bCallHandler = false;
			
			for (auto bp : running)
				bp->hit(ev);
	
		} catch(...) {
		}
		
		try {
			auto hwbplist = hardware_bp.get_items(tid);
			auto ctx = hThread->get_context();
			auto dr6 = ctx.Dr6;
			DebugRegister dr;
			ctx.Dr6 = dr6 & dr.clear_hit_mask;
			hThread->set_context(ctx);
			bool bFoundBreakpoint = false;
			bool bCondition = false;
			
			for (auto hwbp : hwbplist) {
				auto slot = hwbp->get_slot();
				if (slot && (dr6 & dr.hit_mask[slot])) {
					if (!bFoundBreakpoint) 
						if (!bFakeSingleStep)
							ev->set_continue_status(DBG_CONTINUE);
					
					bFoundBreakpoint = true;
					bIsOurs = true;
					
					
					hwbp->hit(ev);
					if (hwbp->is_running()) 
						running_bp.insert(tid, hwbp);
					
					bool bThisCondition = hwbp->eval_condition(ev);
					if (bThisCondition && hwbp->is_automatic()) {
						hwbp->run_action(ev);
						bThisCondition = false;
					}
					
					bThisCondition = (bCondition || bThisCondition);			
				}
			}
			
			if (bFoundBreakpoint)
				bCallHandler = bCondition;

		} catch(...) {
		}
		
		if (is_tracing(tid))
			bCallHandler = true;
		
		if (!bIsOurs && !is_hostile_mode()) 
			hThread->clear_tf();
			
	
		//TODO:  handle ^C  and do ev->set_continue_status(old_continue_status)
		
		return bCallHandler;
	}
	
	
	bool _notify_debug_control_c(ExceptionEvent *ev) {
		if (ev->is_first_chance())
			ev->set_continue_status(DBG_CONTINUE);
		return true;
	}
	
	bool _notify_ms_vc_exception(ExceptionEvent *ev) {
		auto type = ev->get_exception_information(0);
		if (type == 0x1000) {
			auto pszName = ev->get_exception_information(1);
			auto tid = ev->get_exception_information(2);
			auto proc = ev->get_process();
			string name = proc->read_string((void *)pszName);
			if (!name.empty()) {
				
				if (tid == -1)
					tid = ev->get_tid();
				
				Thread *hThread;
				if (proc->has_thread(tid)) {
					hThread = proc->get_thread(tid);
				} else {
					hThread = new Thread(proc->get_pid(), tid);
				}
				
				hThread->set_name(name);
			}
		}
		
		return true;
	}
	
	bool is_tracing(DWORD tid) {
		for (auto tid2 : __tracing)
			if (tid2 == tid)
				return true;
		return false;
	}
	
	void __start_tracing(Thread *th) {
		DWORD tid = th->get_tid();
		if (!is_tracing(tid)) {
			th->set_tf();
			__tracing.insert(__tracing.begin(), tid);
		}
	}
	
	void __stop_tracing(Thread *th) {
		auto tid = th->get_tid();
		
		for (int i=0; i<__tracing.size(); i++) {
			if (__tracing[i] == tid) {
				__tracing.erase(__tracing.begin()+i);
				return;
			}
		}
	}
	
	
	
	////////// EventDispatcher /////////////////
	
	void EventDispatcher(EventHandler *eh) {
		set_event_handler(eh);
	}
	
	EventHandler *get_event_handler() {
		return eh;
	}
	
	EventHandler *set_event_handler(EventHandler *eh) {
		if (this->eh != NULL)
			return eh;
			
		auto prev = this->eh;
		this->eh = eh;
		return prev;
	}
	
	static callback get_handler_method(EventHandler *eh, Event *ev, callback cb) {
		auto code = ev->get_event_code();
		callback method;
		
		if (code == EXCEPTION_DEBUG_EVENT) {
			try {
				method = eh->exception;
			} catch(...) {
				method = cb;
			}
			
			return method;
		}
		
		method = cb;
	
		return method;
	}
	
	EventHandler *EventDispatcher_dispatch(Event *ev) {
		callback pre_handler = NULL;
		callback post_handler = NULL;
		bool bCall_handler = FALSE;
		EventHandler *ret = NULL;
		
		auto ev_code = ev->get_event_code();
		
		cout << "dispatch" << endl;
		
		if (ev_code == EXCEPTION_DEBUG_EVENT) {
			cout << "is exception" << endl;
			auto ex_code = ev->get_exception_code();
			//TODO: control that ex_code is in the keys
			pre_exception_notify_callback(ex_code, (ExceptionEvent *)ev);
			//post_exception_nofity_callback(ex_code, (ExceptionEvent *)ev); 
			
		} else {
			cout << "is not ex" << endl;
			pre_event_notify_callback(ev_code, ev);
			//post_event_nofity_callback(ev_code, ev);
		}
		
		cout << "end dispatch" << endl;
		
		return ret;
	}
	
	void _notify_create_thread(Event *ev) {
		return process->_notify_create_thread(ev->get_tid(), NULL);
	}
	
	bool _notify_load_dll(Event *ev) {
		bool bCallHandler;
		
		cout << "notify load dll 1" << endl;
		bCallHandler = bpc_notify_load_dll(ev);
		auto proc = ev->get_process();
		
		cout << "notify load dll 2" << endl;
		bCallHandler = (proc_notify_load_dll((LoadDLLEvent *)ev) && bCallHandler);
		cout << "notify load dll 3" << endl;



		
		
		if (is_hostile_mode()) {
			cout << "is hostile" << endl;
			
			auto mod = ev->get_module();
			if (mod->match_name("ntdll.dll")) {
				break_at(proc->get_pid(), proc->resolve_label("ntdll!DbgUiRemoteBreakin"), (Hook *)NULL);
			}	
		}
		
		return bCallHandler;
	}
	
	bool proc_notify_load_dll(LoadDLLEvent *ev) {
	
		auto proc = ev->get_process();
		auto base = ev->get_module_base();
		FileHandle *hFile = ev->get_file_handle();
		auto filename = ev->get_filename();

		
		if (!proc->has_module_by_base(base)) {
			cout << "dont have module" << endl;
			auto mod = new Module(base, hFile, filename, ev->get_pid());
			proc->__add_module(mod);

		} else {			
			cout << "have module" << endl;
			auto mod = proc->get_module_by_base(base);
			
			if (mod->get_file_handle() == NULL)
				mod->set_file_handle(hFile);
			
			if (mod->get_pid() == 0)
				mod->set_pid(ev->get_pid());
				
			if (mod->get_filename().empty())
				mod->set_filename(ev->get_filename());
		}

		return true;
	}
	
	bool bpc_notify_load_dll(Event *ev) {
		__set_deferred_breakpoint(ev);
		return true;
	}
	
	void __set_deferred_breakpoint(Event *ev) {
		auto pid = ev->get_pid();
		auto proc = ev->get_process();
		
		for (auto defbp : deferred_bp.get_items(pid)) {
			auto addr = defbp->get_address();
			if (addr) {
				deferred_bp.erase(pid, defbp);
				__set_break(pid, addr, ((CodeBreakpoint *)defbp)->get_action(), defbp->is_one_shot());
			}
		}	
	}
	
	CodeBreakpoint *__set_break(DWORD pid, void *addr, callback action, bool one_shot) {
		
		CodeBreakpoint *cbp;
		
		if (code_bp.contains(pid, addr)) {
			cbp = code_bp.get_item_by_address(pid, addr);
			if (cbp->get_action() != action) {
				cbp->set_action(action);
				cout << "redefined code breakpoint at " << hex << addr << " pid: " << pid << endl;
			}
		} else {
			cbp = define_code_breakpoint(pid, addr, true, action);
		}
		
		if (one_shot) {
			if (!cbp->is_one_shot()) {
				enable_one_shot_code_breakpoint(pid, addr);
			}
		} else {
			if (!cbp->is_one_shot()) {
				enable_code_breakpoint(pid, addr);
			}
		}
		
		return cbp;
	}

	CodeBreakpoint* __set_break_hook(DWORD pid, void* addr, Hook *action, bool one_shot) {

		CodeBreakpoint* cbp;

		if (code_bp.contains(pid, addr)) {
			cbp = code_bp.get_item_by_address(pid, addr);
			if (cbp->get_hook_action() != action) {
				cbp->set_hook_action(action);
				cout << "redefined code breakpoint at " << hex << addr << " pid: " << pid << endl;
			}
		}
		else {
			cbp = define_code_breakpoint_hook(pid, addr, true, action);
		}

		if (one_shot) {
			if (!cbp->is_one_shot()) {
				enable_one_shot_code_breakpoint(pid, addr);
			}
		}
		else {
			if (!cbp->is_one_shot()) {
				enable_code_breakpoint(pid, addr);
			}
		}

		return cbp;
	}


	// what if address is a string? duplicate methods?

	void __clear_break(DWORD pid, void* address) {
		if (has_code_breakpoint(pid, address)) {
			erase_code_breakpoint(pid, address);
		}
	}

	bool break_at(DWORD pid, void* address, callback action) {
		auto bp = __set_break(pid, address, action, false);
		return (bp != NULL);
	}

	bool break_at(DWORD pid, void* address, Hook* action) {
		auto bp = __set_break_hook(pid, address, action, false);
		return (bp != NULL);
	}

	void *resolve_label(DWORD pid, string label) {
		Process* proc = sys->get_process(pid);
		void* addr = NULL;

		if (proc) {
			addr = proc->resolve_label(label);
		}
		else {
			for (auto deferred : deferred_bp.get_items(pid)) {
				if (deferred->get_label() == label) {
					addr = deferred->get_address();
					break;
				}
			}
		}

		return addr;
	}

	bool break_at_label(DWORD pid, string label, Hook* action) {
		void *addr = resolve_label(pid, label);

		if (addr != NULL)
			return break_at(pid, addr, action);
		return false;
	}

	void dont_break_at(DWORD pid, void *address) {
		__clear_break(pid, address);
	}

	void dont_break_at_label(DWORD pid, string label) {
		void *addr = resolve_label(pid, label);

		if (addr != NULL)
			dont_break_at(pid, addr);
	}
	


	
};

