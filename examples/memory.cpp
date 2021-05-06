#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

#include <iostream>

#include "winappdbg.hpp"

int main(void) {
        auto proc = new Process(1932);
        auto map = proc->get_memory_maps();

	cout << "num of maps: " << maps.size() << endl;

        void *addr = maps[0].BaseAddress;
        SIZE_T sz = maps[0].RegionSize;
        int prot = maps[0].Protect;


        if (proc->is_address_writeable(addr))
                cout << "is writeable" << endl;



        char buff[4];

        for (auto m : maps) {

                cout << m.BaseAddress << " " << proc->get_perms_rwx(m.BaseAddress) << endl;

                memset(buff, 0, 4);
                proc->read(m.BaseAddress, buff, 4);

                if (buff[0] == 'M' && buff[1] == 'Z') {
                        cout << "mapped binary found at " << m.BaseAddress << endl;

                        // read/write memory using any type
                        int magic = proc->read_int(m.BaseAddress);
                        cout << "magic: " << hex << magic << endl; 

                        proc->write_int(m.BaseAddress, magic);
			proc->write_string(m.BaseAddress, "MZ");
                }

        }
}



