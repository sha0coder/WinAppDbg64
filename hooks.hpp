/*
	WinAppDbg64
	@sha0coder
	
	Mario Vilas' WinAppDbg port to C++ 64bits
	
	COMPILER FLAGS:
		 -std=C++11
	
	LINKER FLAGS:
		-lpsapi 
	
   
*/

#include <map>
#include <windows.h>

#include "event.hpp"

using namespace std;

class Hook {
protected:
	bool use_hadware_breakpoints = false;
	callback pre_cb = NULL;
	callback post_cb = NULL;
	map<DWORD, DWORD> param_stack;
	
public:
	Hook(callback pre_cb, callback post_cb) {
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
	
	void __call_handler(callback cb, Event *ev) {
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



class ApiHook {
protected:
	EventHandler *evh;
	string mod_name;
	string proc_name;
	callback pre_callback;
	callback post_callback;
	map<DWORD, Hook *> hooks;

public:
	
	ApiHook(EventHandler *evh, string mod_name, string proc_name) {
		this->evh = evh;
		this->mod_name = mod_name;
		this->proc_name = proc_name;
		
		pre_callback = evh->get_pre_callback(proc_name);
		post_callback = evh->get_post_callback(proc_name);
		
		hooks.clear();
	}
	
	void call(Event *ev) {
		auto pid = ev->get_pid();
	}
	
}; // end ApiHook




