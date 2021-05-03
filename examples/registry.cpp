#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "winappdbg.hpp"

using namespace std;

int main(void) {
        char debugger[255];

        System sys;
        sys.reg_read_str(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug", "Debugger", (char *)debugger, 255);
        cout << "JIT debugger: " << debugger << endl;
}


