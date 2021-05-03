#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "winappdbg.hpp"

using namespace std;


int main(void) {
        System sys;

        cout << sys.get_postmortem_debugger() << endl;
        sys.set_postmortem_debugger("\"C:\\Program Files\\Debugging Tools for Windows (x64)\\windbg.exe\" -p %ld -e %ld -g");
        cout << sys.get_postmortem_debugger() << endl;

        sys.auto_postmortem();
	sys.noauto_postmortem();

        sys.add_exclussion_list("testprogram2.exe");
        sys.del_exclussion_list("testprogram2.exe");
}


