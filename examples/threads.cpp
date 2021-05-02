#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

#include "debug.hpp"

using namespace std;


int main(void) {
	auto proc = new Process(2492);
	proc->scan();
	
	auto threads = proc->get_threads();
	
	cout << "number of threads: " << threads.size() << endl;
	
	for (auto t: threads) {
		t->suspend();
		cout << "thread: " << t->get_tid() << endl;
		cout << "program counter: " << hex << t->get_pc() << endl;
		cout << "stack: " << hex << t->get_sp() << endl;
		cout << "sign flag: " << t->get_flags_mask(sign) << endl;
		t->resume();
	}
	
	delete proc;
	
	system("pause");
}

