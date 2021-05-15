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

using namespace std;

typedef BOOL (*hcallback)(Event *);

class Hook {
protected:
	bool use_hadware_breakpoints = false;
	hcallback pre_cb = NULL;
	hcallback post_cb = NULL;
	map<DWORD, DWORD> param_stack;
	
public:
	Hook(callback pre_cb, hcallback post_cb) {
		this->pre_cb = pre_cb;
		this->post_cb = post_cb;
	}
	
	void call(Event *ev) {		
		try {
			__call_handler(pre_cb, ev);
		} catch(...) {
			cout << "call handler crashed" << endl;
		} 
	}
	
	void __post_call_action_hwbp(Event *ev) {
		ev->debug->erase_hardware_breakpoint(ev->get_tid(), ev->breakpoint->get_address()); //TODO: breakpoint is protected?
		try {
			__post_call_action(ev);
		} catch(...) {
		}
	}
	
	void __post_call_action_codebp(Event *ev) {
		ev->debug->dont_break_at(ev->get_pid(), ev->breakpoint->get_address());
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
			ev->hook = this;
		}
	}
	
	
	void hook(Debug *debug, DWORD pid, void *address) {
		debug->break_at(pid, address, this);
	}
	
	void unhook(Debug *debug, DWORD pid, void *address) {
		debug->dont_break_at(pid, address);
	}
	

	
}; // end Hook



typedef bool (*apicallback)(Event *ev);


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
		hook.clear();
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
		get_hook(get_pid())->call(ev);
	}
	
	stirng get_label() {
		stringstream ss;
		ss << mod_name << "!" << api_name;
		return ss.str();
	}
	
	void do_hook(Debug *debug, DWORD pid) {
		get_hook(pid)->do_hook(debug, pid, get_label());
	}
	
	void do_unhook(Debug *debug, DWORD pid) {
		get_hook(pid)->do_unhook(debug, pid, get_label());
	}
	
}; // end ApiHook



