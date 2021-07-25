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
	map<DWORD, DWORD> param_stack;
	
public:
	Hook(hcallback pre_cb, hcallback post_cb) {
		this->pre_cb = pre_cb;
		this->post_cb = post_cb;
	}
	
	bool call(Event *ev) {		
		try {
			__call_handler(pre_cb, ev);
			return true;
		} catch(...) {
			cout << "call handler crashed" << endl;
			return false;
		}
	}
	
	
	
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
	}

	void hook(Debug *dbg, DWORD pid, void *address) {
		dbg->break_at(pid, address, this);
	}
	
	void unhook(Debug *dbg, DWORD pid, void *address) {
		dbg->dont_break_at(pid, address);
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

	void call(Event *ev) {
		auto code = ev->get_event_code();
		if (code == LOAD_DLL_DEBUG_EVENT) {
			__hook_dll(ev);
		}
		else if (code == UNLOAD_DLL_DEBUG_EVENT) {
			__unhook_dll(ev);
		}
	}



	
	
	//TODO: destructor deleting hook objects


	
}; // end EventHandler


