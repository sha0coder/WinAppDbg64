#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "debug.hpp"

using namespace std;


int main(void) {
	
	auto proc = new Process(2492);
	proc->scan();
	
	auto modules = proc->get_modules();
	
	cout << "number of modules: " << modules.size() << endl;
	
	for (auto m: modules) {
		cout << "module: " << m->get_name() << " base: " << hex << m->get_base() << endl;
	}
	
	delete proc;
	
	system("pause");
}

