#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "winappdbg.hpp"

using namespace std;

int main(void) {

	Debug dbg;
	auto proc = dbg.attach(2492);
	dbg.detach();

	auto calc = dbg.exec("C:\\windows\\system32\\calc.exe", "", FALSE, TRUE, TRUE);
	dbg.loop();

	//dbg.stop();
	//dbg.wait();
	//dbg.kill();
	
	
	
	return 0;
}
