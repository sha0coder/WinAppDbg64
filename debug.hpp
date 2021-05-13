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

using namespace std;


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
		//TODO: implement
	}
	
	void disable_process_breakpoints(int pid) {
		//TODO: implement
	}
	
	void disable_thread_breakpoints(int tid) {
		//TODO: implement
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

protected:
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
					auto addr = bp->get_address();
					
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
	
	CodeBreakpoint *define_code_breakpoint(int pid, DWORD64 address, BOOL condition, bpcallback action) {
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
	
	PageBreakpoint *define_page_breakpoint(int pid, DWORD64 address, int pages, BOOL condition, bpcallback action) {
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
	
	HardwareBreakpoint *define_hardware_breakpoint(DWORD tid, DWORD64 address, int trigger_flag, int size_flag, BOOL condition, bpcallback action) {
		HardwareBreakpoint *bp = new HardwareBreakpoint(address, condition, action);
		bp->config(trigger_flag, size_flag);
		bp->set_tid(tid);
		bp->set_pid(sys->get_thread(tid)->get_pid());
		
		auto begin = bp->get_address();
		auto end = begin + bp->get_size();
		
		if (hardware_bp.contains(tid)) {
			for (auto old_bp : hardware_bp.get_items(tid)) {
				auto old_begin = old_bp->get_address();
				auto old_end = old_begin + old_bp->get_size();
				if (MemoryAddresses::do_ranges_intersect(begin, end, old_begin, old_end)) {
					cout << "already exists hardware breakpoint" << endl;
					return NULL;
				}
			}
		} else {
			hardware_bp.insert(tid, bp);
		}
		
		return bp;
	}
	
	BOOL has_code_breakpoint(DWORD pid, DWORD64 address) {
		return code_bp.contains(pid, address);
	}
	
	BOOL has_page_breakpoint(DWORD pid, DWORD64 address) {
		return page_bp.contains(pid, address);
	}
	
	BOOL has_hardware_breakpoint(DWORD tid, DWORD64 address) {
		return hardware_bp.contains(tid, address);
	}
	
	CodeBreakpoint *get_code_breakpoint(DWORD pid, DWORD64 address) {
		if (!code_bp.contains(pid, address)) {
			cout << "no breakpoint at process " << pid << ", address: " << address << endl;
			return NULL;
		}
		
		return code_bp.get_item_by_address(pid, address);
	}
	
	PageBreakpoint *get_page_breakpoint(DWORD pid, DWORD64 address) {
		if (!page_bp.contains(pid, address)) {
			cout << "no breakpoint at process " << pid << ", address: " << address << endl;
			return NULL;
		}
		
		return page_bp.get_item_by_address(pid, address);
	}
	
	HardwareBreakpoint *get_hardware_breakpoint(DWORD tid, DWORD64 address) {
		if (!hardware_bp.contains(tid, address)) {
			cout << "no hw breakpoint at thread " << tid << ", address: " << address << endl;
			return NULL;
		}
		
		return hardware_bp.get_item_by_address(pid, address);
	}
	
	void enable_code_breakpoint(DWORD pid, DWORD64 address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_code_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_enable(proc);
	}
	
	void enable_page_breakpoint(DWORD pid, DWORD64 address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_page_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_enable(proc);
	}
	
	void enable_hardware_breakpoint(DWORD tid, DWORD64 address) {
		auto t = this->sys->get_thread(tid);
		auto bp = get_hardware_breakpoint(tid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_enable(t);
	}
	
	void enable_one_shot_code_breakpoint(DWORD pid, DWORD64 address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_code_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_one_shot(proc);
	}
	
	void enable_one_shot_page_breakpoint(DWORD pid, DWORD64 address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_page_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_one_shot(proc);
	}
	
	void enable_one_shot_hardware_breakpoint(DWORD tid, DWORD64 address) {
		auto t = this->sys->get_thread(pid);
		auto bp = get_hardware_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_one_shot(t);
	}
	
	void disable_code_breakpoint(DWORD pid, DWORD64 address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_code_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_disable(proc);
	}
	
	void disable_page_breakpoint(DWORD pid, DWORD64 address) {
		auto proc = this->sys->get_process(pid);
		auto bp = get_page_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_disable(proc);
	}
	
	void disable_hardware_breakpoint(DWORD tid, DWORD64 address) {
		auto t = this->sys->get_thread(tid);
		auto bp = get_hardware_breakpoint(pid, address);
		if (bp->is_running()) {
			__del_running_bp_from_all_threads(bp);
		}
		
		bp->do_disable(t);
	}
	
	void erase_code_breakpoint(DWORD pid, DWORD64 address) {
		auto bp = get_code_breakpoint(pid, address);
		if (!bp->is_disabled()) 
			disable_code_breakpoint(pid, address);
			
		code_bp.erase(pid, bp);
	}
	
	void erase_page_breakpoint(DWORD pid, DWORD64 address) {
		auto bp = get_page_breakpoint(pid, address);
		if (!bp->is_disabled())
			disable_page_breakpoint(pid, address);
		
		page_bp.erase(pid, bp);
	}
	
	void erase_hardware_breakpoint(DWORD tid, DWORD64 address) {
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
	
	BOOL _notify_guard_page(Event *ev) {
		auto address = ev->get_fault_address();
		auto pid = ev->get_pid();
		BOOL call_handler = TRUE;
		BOOL condition;
		
		auto mask = ~(MemoryAddresses::page_size() - 1);
		address &= mask;
		
		
		for (auto bp : page_bp.get_items(pid)) {
			auto begin = bp->get_address();
			auto end = begin + bp->get_size();
			
			if (address >= begin && address <= end)	 {
				
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
	
	BOOL _notify_breakpoint(Event *ev) {
		auto address = ev->get_exception_address();
		auto pid = ev->get_pid();
		BOOL call_handler = TRUE;
		BOOL condition;
		
		auto bp = code_bp.get_item(pid, address);
		if (bp != NULL) {
			if (!bp->is_disabled()) {
				auto thread = ev->get_thread();
				thread->set_pc(address);
				event->set_continue_status(DBG_CONTINUE);
				bp->hit(ev);
				
				if (bp->is_running()) 
					running_bp.insert(ev->thread_id(), bp);
				
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
			if (in_hostile_mode()) 
				ev->set_continue_status(DBG_EXCEPTION_NOT_HANDLED);
			else
				ev->set_continue_status(DBG_CONTINUE);
			
		}
		
		return call_handler;
	}
	
};

