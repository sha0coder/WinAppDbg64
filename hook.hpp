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

#include <map>
#include <windows.h>

#include "event.hpp"
#include "debug.hpp"

typedef BOOL (*hcallback)(Event *);

class Hook {
protected:
	bool use_hadware_breakpoints = false;
	hcallback pre_cb = NULL;
	hcallback post_cb = NULL;
	//map<DWORD, DWORD> param_stack;
	/*
	vector<DWORD> param_stack;
	vector<DWORD> pre_cb_args; // which type is this?
	vector<DWORD> post_cb_args; // which type is this?
	*/
	int param_count = 0;

public:
	Hook() {
	}

	Hook(hcallback pre_cb, hcallback post_cb) {
		this->pre_cb = pre_cb;
		this->post_cb = post_cb;
	}
	/*
	void set_pre_cb_args(vector<DWORD> pre_cb_args) {
		this->pre_cb_args = pre_cb_args;
	}

	void set_post_cb_args(vector<DWORD> post_cb_args) {
		this->post_cb_args = post_cb_args;
	}*/

	void set_param_count(int param_count) {
		this->param_count = param_count;
	}


	void *_get_return_address(Process *proc, Thread *thread) {
		return proc->read_pointer((void *)thread->get_sp());
	}

	DWORD64 _get_return_value(Thread* thread) {
		CONTEXT ctx = thread->get_context();
		return ctx.Rax;
	}

	vector<DWORD64> _get_function_arguments(Process *proc, Thread *thread) {
		vector<DWORD64> args;
		auto rsp = thread->get_sp();

		for (int i = 0; i < param_count; i++) {
			args.push_back(proc->read_long_long((void *)(rsp + (8 * i))));
		}

		return args;
	}



	


	bool call(Event *ev) {
		auto dbg = ev->get_debug();
		auto pid = ev->get_pid();
		auto tid = ev->get_tid();
		auto proc = ev->get_process();
		auto thread = ev->get_thread();

		void *ra = _get_return_address(proc, thread);
		auto params = _get_function_arguments(proc, thread);
		
		__push_params(tid, params);
		bool bHookedReturn = false;

		if (ra != NULL && post_cb != NULL) {
			auto use_hardware_breakpoints = this->use_hadware_breakpoints;
			if (use_hardware_breakpoints) {
				try {
					dbg->define_hardware_breakpoint(tid, ra, dbg->BP_BREAK_ON_EXECUTION, dbg->BP_WATCH_BYTE, true, this->__postCallAction_hwbp);
					dbg->enable_one_shot_hardware_breakpoint(tid, ra);
					bHookedReturn = true;
				}
				catch (...) {
					use_hardware_breakpoints = false;
					cout << "failed to set a hardware breakpoint at return address " << ra << " for thread id " << tid << endl;
				}
			}

			if (!use_hardware_breakpoints) {
				try {
					dbg->break_at(pid, ra, this->__postCallAction_codebp);
					bHookedReturn = true;
				}
				catch (...) {
					cout << "failed to set a code breakpoint at return address " << ra << " for thread id " << tid << endl;
				}
			}
		}

		if (this->pre_cb_args.empty()) {
			this->__callHandler(pre_cb, ev, ra, pre_cb_args, params);
		}
		else {
			this->__callHandler(pre_cb, ev, ra, params);
		}

		if (!bHookedReturn) {
			this->__pop_params(tid);
		}

	}
	
	
	/*
	void __post_call_action_hwbp(Debug *debug, Event *ev) {
		debug->erase_hardware_breakpoint(ev->get_tid(), ev->get_address()); //TODO: breakpoint is protected?
		try {
			__post_call_action(ev);
		} catch(...) {
		}
	}
	
	void __post_call_action_codebp(Debug *dbg, Event *ev) {
		dbg->dont_break_at(ev->get_pid(), ev->breakpoint->get_address());
		try {
			__post_call_action(ev);
		} catch(...) {
		}
	}
	
	
	void __post_call_action(Event *ev) {
		auto thread = ev->get_thread();
		try {
			__call_handler(post_cb, ev);
		} catch(...) {
		}
	}
	
	void __call_handler(hcallback cb, Event *ev) {
		if (cb != NULL) {
			//ev->set_hook(this);
			cb(ev);
		}
	}*/

	void hook(Debug *dbg, DWORD pid, void *address) {
		dbg->break_at(pid, address, this);
	}

	void hook(Debug* dbg, DWORD pid, string label) {
		dbg->break_at_label(pid, label, this);
	}
	
	void unhook(Debug *dbg, DWORD pid, void *address) {
		dbg->dont_break_at(pid, address);
	}

	void unhook(Debug* dbg, DWORD pid, string label) {
		dbg->dont_break_at_label(pid, label);
	}
	

	
}; // end Hook



typedef BOOL (*apicallback)(Event *ev);


class ApiHook {
protected:
	apicallback pre_callback = NULL;
	apicallback post_callback = NULL;
	map<DWORD, Hook *> hooks; // pid, hook

public:
	string mod_name = "";
	string api_name = "";
	
	
	ApiHook(string mod_name, string api_name, apicallback pre_callback, apicallback post_callback) {
		this->mod_name = mod_name;
		this->api_name = api_name;
		this->pre_callback = pre_callback;
		this->post_callback = post_callback;
		hooks.clear();
	}
	
	vector<DWORD> get_pids() {
		vector<DWORD> pids;
		auto pos = hooks.begin();
		while (pos != hooks.end()) {
			pids.push_back(pos->first);
			pos++;
		}
		
		return pids;
	}
	
	bool has_pid(DWORD pid) {
		auto pos = hooks.begin();
		while (pos != hooks.end()) {
			if (pos->first == pid)
				return true;
			pos++;
		}
		return false;
	}
	
	Hook *get_hook(DWORD pid) {
		Hook *hook;
		
		if (has_pid(pid)) {
			hook = hooks[pid];
		} else {
			hook = new Hook(pre_callback, post_callback);
			hooks.insert(make_pair(pid, hook));
		}
		
		return hook;
	}
	
	void call(Event *ev) {
		get_hook(ev->get_pid())->call(ev);
	}
	
	string get_label() {
		stringstream ss;
		ss << mod_name << "!" << api_name;
		return ss.str();
	}


	
	void do_hook(Debug *dbg, DWORD pid) {
		get_hook(pid)->hook(dbg, pid, get_label());
	}
	
	void do_unhook(Debug *dbg, DWORD pid) {
		get_hook(pid)->unhook(dbg, pid, get_label());
	}
	
	
}; // end ApiHook




class EventHandler {
protected:
	MapVector<string, ApiHook *> api_hooks;
	
public:
	callback exception = NULL;
	
	EventHandler() {
		api_hooks.clear();
	}

	~EventHandler() {
		api_hooks.clear();
	}

	vector<ApiHook*> __get_hooks_for_dll(Event *ev) {
		vector<ApiHook*> result;
		SuperString module_filepath(ev->get_module()->get_filename());
		if (!module_filepath.empty()) {
			auto spl = module_filepath.split('\\');
			auto module = spl[spl.size() - 1];
			for (auto apihook : api_hooks.get_items(module)) {
				result.push_back(apihook);
			}
		}

		return result;
	}

	void __hook_dll(Event *ev) {
		auto dbg = ev->get_debug();
		auto pid = ev->get_pid();
		for (auto apihook : __get_hooks_for_dll(ev)) {
			apihook->do_hook(dbg, pid);
		}
	}

	void __unhook_dll(Event *ev) {
		auto dbg = ev->get_debug();
		auto pid = ev->get_pid();
		for (auto apihook : __get_hooks_for_dll(ev)) {
			apihook->do_unhook(dbg, pid);
		}
	}

	virtual void create_thread(CreateThreadEvent *ev) {}
	virtual void load_dll(LoadDLLEvent *ev) {}

	void call(Event *ev) {
		auto code = ev->get_event_code();
		if (code == LOAD_DLL_DEBUG_EVENT) {
			__hook_dll(ev);
		}
		else if (code == UNLOAD_DLL_DEBUG_EVENT) {
			__unhook_dll(ev);
		}

		string method = ev->event_method;

		if (method == "create_thread") {
			this->create_thread((CreateThreadEvent *)ev);
		}

		if (method == "load_dll") {
			this->load_dll((LoadDLLEvent *)ev);
		}
	}



	
	
	//TODO: destructor deleting hook objects


	
}; // end EventHandler


