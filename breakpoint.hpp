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

#include "event.hpp"


//// Breakpoint ////

typedef bool (*bpcallback)(Event *);

class Breakpoint {
protected:
	void *address;
	int state;
	int size;
	bpcallback action = NULL;
	Hook *hook_action = NULL;
	BOOL condition;
	DWORD pid = 0;
	DWORD tid = 0;
	string label = "";
	
public:
	static const int DISABLED = 0;
	static const int ENABLED = 1;
	static const int ONESHOT = 2;
	static const int RUNNING = 3;
	
	
	Breakpoint(void *address, BOOL condition, bpcallback action) {
		this->address = address;
		this->state = Breakpoint::DISABLED;
		this->action = action;
		size = 1;
	}

	Breakpoint(void* address, BOOL condition, Hook *action) {
		this->address = address;
		this->state = Breakpoint::DISABLED;
		this->hook_action = action;
		size = 1;
	}
	
	Breakpoint(void *address, int size, BOOL condition, bpcallback action) {
		this->address = address;
		this->state = Breakpoint::DISABLED;
		this->size = size;
		this->action = action;
	}
		
	BOOL operator== (Breakpoint *bp) {
		if (get_address() == bp->get_address() && 
			get_pid() == bp->get_pid() &&
			get_tid() == bp->get_tid()) 
			return TRUE;
		return FALSE;
	}
	
	void set_pid(DWORD pid) {
		this->pid = pid;
	}
	
	void set_tid(DWORD tid) {
		this->tid = tid;
	}

	string get_label() {
		return label;
	}

	void set_label(string lbl) {
		label = lbl;
	}
	
	bpcallback get_action() {
		return action;
	}

	Hook *get_hook_action() {
		return hook_action;
	}
	
	DWORD get_pid() {
		return pid;
	}
	
	DWORD get_tid() {
		return tid;
	}
	
	BOOL is_automatic() {
		if (action == NULL)
			return FALSE;
		return TRUE;
	}
		
	BOOL eval_condition(Event *ev) {
		/*TODO: implement conditions
		
			bool cond = get_condition()
		if (cond)
			return true;
		*/		
		
		return true;
	}
	
	
	BOOL is_disabled() {
		if (state == Breakpoint::DISABLED) 
			return TRUE;
		return FALSE;
	}
	
	BOOL is_enabled() {
		if (state == Breakpoint::ENABLED)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_one_shot() {
		if (state == Breakpoint::ONESHOT)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_running() {
		if (state == Breakpoint::RUNNING)
			return TRUE;
		return FALSE;
	}
	
	BOOL is_here(void *address) {
		if (this->address == address) 
			return TRUE;
		return FALSE;
	}
	
	int get_size() {
		return size;
	}
	
	void *get_address() {
		return address;
	}
	
	void *get_end_address() {
		return (char *)address+size;
	}
	
	int get_state() {
		return state;
	}
	
	void set_action(bpcallback action) {
		this->action = action;
	}

	void set_hook_action(Hook* action) {
		this->hook_action = action;
	}
	
	BOOL run_action(Event *ev) {
		if (action == NULL && hook_action == NULL)
			return TRUE;
			
		if (action != NULL)
			return action(ev);	//TODO: use try/catch?
		return hook_action->call(ev);
	}
	
	void _bad_transition(int state) {
		cout << "bad transition from " << this->state << " to " << state << endl;
	}
	
	void disable() {
		state = Breakpoint::DISABLED;
	}
	
	void enable() {
		state = Breakpoint::ENABLED;
	}
	
	void one_shot() {
		state = Breakpoint::ONESHOT;
	}
	
	void run() {
		state = Breakpoint::RUNNING;
	}
	
	void hit(Event *ev) {
		
		//TODO: set the breakpoint on the event, but in a one file mutiple class thats not possible
		
		switch(state) {
			case Breakpoint::ENABLED:
				run();
				break;
				
			case Breakpoint::RUNNING:
				enable();
				break;
				
			case Breakpoint::ONESHOT:
				disable();
				break;
				
			case Breakpoint::DISABLED:
				cout << "hit a disabled breakpoint at " << address << endl;
				break;
		}
	}
	
}; // end Breakpoint

class CodeBreakpoint : public Breakpoint {
protected:
	char prev_value = '\xcc';
	char instruction = '\xcc';
	int instruction_sz = 1;
	
public:
	string type_name = "code breakpoint";
	
	CodeBreakpoint(void *address, BOOL condition, bpcallback action) : Breakpoint(address, condition, action) {
	}

	CodeBreakpoint(void* address, BOOL condition, Hook *action) : Breakpoint(address, condition, action) {
	}
	
	void __set_bp(Process *p) {
		this->prev_value = p->read_char((void *)get_address());
		if (prev_value == instruction) 
			cout << "possible overlapping code breakpoint at " << get_address() << endl;
		
		p->write_char(get_address(), instruction);
	}
	
	void __clear_bp(Process *p) {
		char curr_value;
		
		curr_value = p->read_char(get_address());
		if (curr_value == instruction) {
			p->write_char(get_address(), prev_value);
		} else {
			prev_value = curr_value;
			cout << "overwriten code breakpoint at " << get_address() << endl;
			
		}
	}
	
	void do_disable(Process *p) {
		if (!is_disabled() && !is_running())
			__clear_bp(p);
		
		disable();
	}
	
	void do_enable(Process *p) {
		if (!is_enabled() && !is_one_shot()) 
			__set_bp(p);
		
		enable();
	}
	
	void do_one_shot(Process *p) {
		if (!is_enabled() && !is_one_shot())
			__set_bp(p);
		
		one_shot();
	}
	
	void do_running(Process *p, Thread *t) {
		if (is_enabled()) {
			__clear_bp(p);
			t->set_flags_trap();
		}
		
		run();
	}
	
}; //  end CodeBreakpoint


//// PageBreakpoint ////
//TODO: refactor breakpoints

class PageBreakpoint : public Breakpoint { 
protected:
	char prev_value = '\xcc';
	char instruction = '\xcc';
	int instruction_sz = 1;
	float floordiv_align;
	float truediv_align;
	
public:
	string type_name = "page breakpoint";
	
	//TODO: optimize cache page_size()
	
	PageBreakpoint(void *address, int pages, BOOL condition, bpcallback action) : Breakpoint(address, pages * MemoryAddresses::page_size(), condition, action) {
		floordiv_align = floor((DWORD64)address / MemoryAddresses::page_size());
		truediv_align = (DWORD64)address /  MemoryAddresses::page_size();
	}
	
	int get_size_in_pages() {
		return floor(get_size() / MemoryAddresses::page_size());
	}
	
	void __set_bp(Process *p) {
		int new_protect;
		
		auto m = p->mquery(get_address());
		new_protect = m.Protect | PAGE_GUARD;
		p->mprotect(get_address(), get_size(), new_protect);
	}
	
	void __clear_bp(Process *p) {
		int new_protect;
		
		auto m = p->mquery(get_address());
		new_protect = m.Protect | (0xffffffff ^ PAGE_GUARD);
		p->mprotect(get_address(), get_size(), new_protect);
	}
	
	void do_disable(Process *p) {
		if (!is_disabled())
			__clear_bp(p);
		
		disable();
	}
	
	void do_enable(Process *p) {
		if (!is_enabled() && !is_one_shot()) 
			__set_bp(p);
		
		enable();
	}
	
	void do_one_shot(Process *p) {
		if (!is_enabled() && !is_one_shot())
			__set_bp(p);
		
		one_shot();
	}
	
	void do_running(Process *p, Thread *t) {
		t->set_flags_trap();	
		run();
	}
	
	
}; // end PageBreakpoint



//// DebugRegister ////
class DebugRegister {
protected:
public:
	static const int BREAK_ON_EXECUTION = 0;
	static const int BREAK_ON_WRITE = 1;
	static const int BREAK_ON_ACCESS = 3;
	static const int BREAK_ON_IO_ACCESS = 2;
	
	static const int WATCH_BYTE = 0;
	static const int WATCH_WORD = 1;
	static const int WATCH_DWORD = 3;
	static const int WATCH_QWORD = 2;
	
	const unsigned long long register_mask = 0xffffffffffffffff;
	
	unsigned long long enable_mask[4] = {
		1 << 0,
		1 << 2,
		1 << 4,
		1 << 6
	};
	
	unsigned long long disable_mask[4] = {
		register_mask ^ (1 << 0),
		register_mask ^ (1 << 2),
		register_mask ^ (1 << 4),
		register_mask ^ (1 << 6),
	};
	
	unsigned long long trigger_mask[4][4][2] = {
		// Dr0 (bits 16-17)
		 {
            {(0 << 16), (3 << 16) ^ register_mask},  // execute
            {(1 << 16), (3 << 16) ^ register_mask},  // write
            {(2 << 16), (3 << 16) ^ register_mask},  // io read
            {(3 << 16), (3 << 16) ^ register_mask},  // access
        },
        // Dr1 (bits 20-21)
        {
		    {(0 << 20), (3 << 20) ^ register_mask},  // execute
            {(1 << 20), (3 << 20) ^ register_mask},  // write
            {(2 << 20), (3 << 20) ^ register_mask},  // io read
            {(3 << 20), (3 << 20) ^ register_mask},  // access
        },
        // Dr2 (bits 24-25)
        {
		    {(0 << 24), (3 << 24) ^ register_mask},  // execute
            {(1 << 24), (3 << 24) ^ register_mask},  // write
            {(2 << 24), (3 << 24) ^ register_mask},  // io read
            {(3 << 24), (3 << 24) ^ register_mask},  // access
        },
        // Dr3 (bits 28-29)
        {
		    {(0 << 28), (3 << 28) ^ register_mask},  // execute
            {(1 << 28), (3 << 28) ^ register_mask},  // write
            {(2 << 28), (3 << 28) ^ register_mask},  // io read
            {(3 << 28), (3 << 28) ^ register_mask},  // access
        },
	};
	
	unsigned long long int watch_mask[4][4][2] = {
        // Dr0 (bits 18-19)
        {
            {(0 << 18), (3 << 18) ^ register_mask},  // byte
            {(1 << 18), (3 << 18) ^ register_mask},  // word
            {(2 << 18), (3 << 18) ^ register_mask},  // qword
            {(3 << 18), (3 << 18) ^ register_mask},  // dword
        },
        // Dr1 (bits 22-23)
        {
            {(0 << 23), (3 << 23) ^ register_mask},  // byte
            {(1 << 23), (3 << 23) ^ register_mask},  // word
            {(2 << 23), (3 << 23) ^ register_mask},  // qword
            {(3 << 23), (3 << 23) ^ register_mask},  // dword
        },
        // Dr2 (bits 26-27)
        {
            {(0 << 26), (3 << 26) ^ register_mask},  // byte
            {(1 << 26), (3 << 26) ^ register_mask},  // word
            {(2 << 26), (3 << 26) ^ register_mask},  // qword
            {(3 << 26), (3 << 26) ^ register_mask},  // dword
        },
        // Dr3 (bits 30-31)
        {
            {(0 << 30), (3 << 31) ^ register_mask},  // byte
            {(1 << 30), (3 << 31) ^ register_mask},  // word
            {0xffffffff80000000, (3 << 31) ^ register_mask},  // qword    compiler trick
            {0xffffffffc0000000, (3 << 31) ^ register_mask},  // dword 	  compiler trick
        }
	};
	
	unsigned long long clear_mask[4] = {
        register_mask ^ ( (1 << 0) + (3 << 16) + (3 << 18) ),    // Dr0
        register_mask ^ ( (1 << 2) + (3 << 20) + (3 << 22) ),    // Dr1
        register_mask ^ ( (1 << 4) + (3 << 24) + (3 << 26) ),    // Dr2
        register_mask ^ ( (1 << 6) + (3 << 28) + (3 << 30) )     // Dr3
	};
	
	unsigned long long general_detect_mask = (1 << 13);
	
	unsigned long long hit_mask[4] = {
        (1 << 0),   // Dr0
        (1 << 1),   // Dr1
        (1 << 2),   // Dr2
        (1 << 3),   // Dr3
	};
	
	unsigned long long hit_mask_all = hit_mask[0]|hit_mask[0]|hit_mask[0]|hit_mask[0];
	unsigned long long clear_hit_mask = register_mask ^ hit_mask_all;
	unsigned long long debug_access_mask = (1 << 13);
	unsigned long long single_step_mask = (1 << 14);
	unsigned long long task_switch_mask = (1 << 15);
	unsigned long long clear_dr6_mask = register_mask ^ (hit_mask_all | debug_access_mask | single_step_mask | task_switch_mask);
	
	
	unsigned long long debug_ctrl_msr = 0x1d9;
	unsigned long long last_branch_record = (1 << 0);
	unsigned long long branch_trap_flag = (1 << 1);
	unsigned long long pin_contro[4] = {
		    (1 << 2),   // PB1
            (1 << 3),   // PB2
            (1 << 4),   // PB3
            (1 << 5),   // PB4
	};
	
	unsigned long long last_branch_to_ip = 0x1dc;
	unsigned long long last_branch_from_ip = 0x1db;
	unsigned long long last_exception_to_ip = 0x1de;
	unsigned long long last_exception_from_ip = 0x1dd;
	
	
	void clear_bp(CONTEXT *ctx, int reg) {
		ctx->Dr7 &= clear_mask[reg];
		switch(reg) {
			case 0:
				ctx->Dr0 = 0;
				break;
			case 1:
				ctx->Dr1 = 0;
				break;
			case 2:
				ctx->Dr2 = 0;
				break;
			case 3:
				ctx->Dr3 = 0;
				break;
			case 6:
				ctx->Dr6 = 0;
				break;
			case 7:
				ctx->Dr7 = 0;
				break;
		}
	}
	
	void set_bp(CONTEXT *ctx, int reg, void *address, int trigger, int watch) {
		unsigned long long or_mask;
		unsigned long long and_mask;
		DWORD64 Dr7;
		
		Dr7 = ctx->Dr7;
        Dr7 |= enable_mask[reg];
        or_mask = trigger_mask[reg][trigger][0];
        and_mask = trigger_mask[reg][trigger][1];
        Dr7 &= and_mask;
        Dr7 |= or_mask;
        
        or_mask = watch_mask[reg][watch][0];
        and_mask = watch_mask[reg][watch][1];
        Dr7 &= and_mask;
        Dr7 |= or_mask;
        ctx->Dr7 = Dr7;
        
        
        switch(reg) {
			case 0:
				ctx->Dr0 = (DWORD64)address;
				break;
			case 1:
				ctx->Dr1 = (DWORD64)address;
				break;
			case 2:
				ctx->Dr2 = (DWORD64)address;
				break;
			case 3:
				ctx->Dr3 = (DWORD64)address;
				break;
			case 6:
				ctx->Dr6 = (DWORD64)address;
				break;
			case 7:
				ctx->Dr7 = (DWORD64)address;
				break;
		}
	}
	
	int find_slot(CONTEXT *ctx) {
		int slot;
		DWORD64 Dr7;
		
		Dr7 = ctx->Dr7;
		slot = 0;
		
		for (int i=0; i<4; i++) {
			if ((Dr7 & enable_mask[i]) == 0) {
				return slot;
			}
			slot++;
		}
		
		return -1;
	}
	
};
////

//// HardwareBreakpoint ////

class HardwareBreakpoint : public Breakpoint {
protected:	
	int valid_triggers[3] = {
		BREAK_ON_EXECUTION,
		BREAK_ON_WRITE,
		BREAK_ON_ACCESS
	};
	
	int valid_watch_sizes[4] = {
		WATCH_BYTE,
		WATCH_WORD,
		WATCH_DWORD,
		WATCH_QWORD
	};
	
	int __trigger;
	int __watch;
	int __slot;
	

public:
	int BREAK_ON_EXECUTION = DebugRegister::BREAK_ON_EXECUTION;
	int BREAK_ON_WRITE = DebugRegister::BREAK_ON_WRITE;
	int BREAK_ON_ACCESS = DebugRegister::BREAK_ON_IO_ACCESS;
	int WATCH_BYTE = DebugRegister::WATCH_BYTE;
	int WATCH_WORD = DebugRegister::WATCH_WORD;
	int WATCH_DWORD = DebugRegister::WATCH_DWORD;
	int WATCH_QWORD = DebugRegister::WATCH_QWORD;
	
	
	string type_name = "hardware breakpoint";
	
	HardwareBreakpoint(void *address, BOOL condition, bpcallback action) : Breakpoint(address, condition, action) {
	}
	
	//TODO: implement conditions in all breakpoints
	
	// use constructor without size.
	void config(int trigger_flag, int size_flag) {
		BOOL trigger_ok;
		int size = 1;
		
		switch(size_flag) {
			case DebugRegister::WATCH_BYTE:
				size = 1;
				break;
			case DebugRegister::WATCH_WORD:
				size = 2;
				break;
			case DebugRegister::WATCH_DWORD:
				size = 4;
				break;
			case DebugRegister::WATCH_QWORD:
				size = 8;
				break;
			default:
				cout << "invalid size flag for hardware breakpoint" << endl;
				return;
		}
		
		trigger_ok = FALSE;
		for (int i=0; i<3; i++) {
			if (valid_triggers[i] == trigger_flag) {
				trigger_ok = TRUE;
				return;
			}
		}
		
		if (!trigger_ok) {
			cout << "invalid trigger flag for harware breakpoint" << endl;
			return;
		}
		
		this->size = size;
		__trigger = trigger_flag;
		__watch = size_flag;
		__slot = 0;
	}
	
	void __clear_bp(Thread *t) {
		CONTEXT ctx;
		
		if (__slot) {
			t->suspend();
			ctx = t->get_context();
			auto dr = new DebugRegister();
			dr->clear_bp(&ctx, __slot);  //TODO: implement
			delete dr;
			t->set_context(ctx);
			__slot = 0;
			t->resume();
		}
	}
	
	void __set_bp(Thread *t) {
		CONTEXT ctx;
		
		if (!__slot) {
			t->suspend();
			auto dr = new DebugRegister();
			__slot = dr->find_slot(&ctx);
		
			if (!__slot) {
				cout << "No available hardware breakpoint slots for thread id " << t->get_tid() << " thread suspended." << endl;
				delete dr;
				return;
				//TODO: remain suspended? resume it?
			}
			
			dr->set_bp(&ctx, __slot, get_address(), __trigger, __watch);
			delete dr;
			t->set_context(ctx);
			t->resume();
		}
	}
		
	int get_slot() {
		return __slot;
	}
	
	int get_trigger() {
		return __trigger;
	}
	
	int get_watch() {
		return __watch;
	}
	
	void do_disable(Thread *t) {
		if (!is_disabled()) 
			__clear_bp(t);
		
		disable();
	}
	
	void do_enable(Thread *t) {
		if (!is_enabled() && !is_one_shot())
			__set_bp(t);
		enable();
	}
	
	void do_one_shot(Thread *t) {
		if (!is_enabled() && !is_one_shot())
			__set_bp(t);
			
		one_shot();
	}
	
	void do_running(Thread *t) {
		__clear_bp(t);
		run();
		t->set_flags_trap();
	}
	
	
}; // end HardwareBreakpoint

