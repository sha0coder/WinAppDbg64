#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "winappdbg.hpp"

using namespace std;

int main(void) {

        System sys;
        sys.scan_services();
        auto services = sys.get_services();
        for (auto service : services) {

                if (service->is_running())
                        cout << "(running) name: "<< service->get_name() << " pid: " << service->get_pid() << endl;

                if (service->is_stopped())
                        cout << "(stopped) name: "<< service->get_name() << endl;

                if (service->is_paused())
                        cout << "(paused) name: "<< service->get_name() << " pid: " << service->get_pid() << endl;

        }

        auto service = sys.get_service_by_name("Themes");
        service->change_description("the themes.");
        service->stop();
        service->start();

}
