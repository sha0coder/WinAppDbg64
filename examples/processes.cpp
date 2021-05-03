#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "winappdbg.hpp"


int main(void) {

        System sys;
        sys.scan_processes();

        for (auto proc : sys.get_processes()) {
                cout << proc->get_name() << endl;
        }

        cout << "explorer pid: " << sys.get_explorer_pid() << endl;

        auto cmd = sys.get_process_by_name("cmd.exe");
        cout << "cmd ppid: " << cmd->get_ppid() << endl;
	cout << cmd->is_debugged() << endl;

	cmd.scan()
	cout << cmd.get_threads().size() << endl;
	cout << cmd.get_modules().size() << endl;

}
