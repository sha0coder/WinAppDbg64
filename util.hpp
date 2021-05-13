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

#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <dbghelp.h>
#include <shlobj.h>
#include <winver.h>
#include <winbase.h>
#include <ntstatus.h>
#include <math.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <map>

#define EXCEPTION_WX86_BREAKPOINT 0x4000001F
#define MS_VC_EXCEPTION 0x406D1388
//#define STATUS_POSSIBLE_DEADLOCK 0xc0000194



using namespace std;


const DWORD64 END_ADDRESS = 0x7ffffff0000;
const DWORD64 DEFAULT_PAGE_SIZE = 0x1000; // default page size for when can not be calculated in runtime.



//// TIB ////

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

//// MSR registers ////

typedef struct _SYSDBG_VIRTUAL {
    PVOID Address;
    PVOID Buffer;
    ULONG Request;
} SYSDBG_VIRTUAL, *PSYSDBG_VIRTUAL;

typedef enum _DEBUG_CONTROL_CODE {
    DebugSysGetTraceInformation=1,
    DebugSysSetInternalBreakpoint, 
    DebugSysSetSpecialCall,
    DebugSysClerSpecialCalls,  
    DebugSysQuerySpecialCalls, 
    DebugSysBreakpointWithStatus,
    DebugSysGetVersion,
    DebugSysReadVirtual = 8, 
    DebugSysWriteVirtual = 9,
    DebugSysReadPhysical = 10,
    DebugSysWritePhysical = 11,
    DebugSysReadControlSpace=12, 
    DebugSysWriteControlSpace, 
    DebugSysReadIoSpace, 
    DebugSysSysWriteIoSpace,
    DebugSysReadMsr,
    DebugSysWriteMsr,
    DebugSysReadBusData,
    DebugSysWriteBusData,
    DebugSysCheckLowMemory, 
} DEBUG_CONTROL_CODE;




//// MemoryAddresses ////

class MemoryAddresses {
protected:
public:
	static DWORD page_size() {
		SYSTEM_INFO sys_info;
		
		try {
			GetSystemInfo(&sys_info);
			return sys_info.dwPageSize;
			
		} catch (...) {
			return DEFAULT_PAGE_SIZE;
		}

		return DEFAULT_PAGE_SIZE;		
	}
	
	static DWORD64 align_address_to_page_start(DWORD64 address) {
		return address - (address % MemoryAddresses::page_size());
	}
	
	static DWORD64 align_address_to_page_end(DWORD64 address) {	
		return address + MemoryAddresses::page_size() - (address % MemoryAddresses::page_size());
	}
	
	static vector<DWORD64> align_address_range(DWORD64 begin, DWORD64 end) {
		DWORD64 tmp;
		vector<DWORD64> range;
		
		if (end == 0)
			end = END_ADDRESS; 
			
		if (end < begin) {
			tmp = end;
			end = begin;
			begin = tmp;
		}
		
		cout << "end1: " << end << endl;
		
		begin = MemoryAddresses::align_address_to_page_start(begin);
		if (end != MemoryAddresses::align_address_to_page_start(end))
			end = MemoryAddresses::align_address_to_page_end(end);
			
		cout << "end2: " << end << endl;
		
		range.push_back(begin);
		range.push_back(end);
		
		return range;
	}
	
	static SIZE_T get_buffer_size_in_pages(DWORD64 address, SIZE_T size) {
		DWORD64 begin, end;
		
		vector<DWORD64> range = MemoryAddresses::align_address_range(address, address + size);
		begin = range[0];
		end = range[1];
		
		return ((end - begin) / MemoryAddresses::page_size());
	}
	
	static BOOL do_ranges_intersect(DWORD64 begin, DWORD64 end, DWORD64 old_begin, DWORD64 old_end) {
		return (old_begin <= begin < old_end) ||
				(old_begin < end <= old_end) ||
				(begin <= old_begin < end) ||
				(begin < old_end <= end);
	}
	
	
}; // end MemoryAddresses




//// Box abstraction ////

template <typename T>
class Box {
private:
	map<DWORD, vector<T>> db;
	
public:
	
	map<DWORD, vector<T>> get_map() {
		return db;
	}
	
	vector<DWORD> get_keys() {
		vector<DWORD> keys;
		
		auto pos = db.begin();
		while (pos != db.end()) {
			keys.push_back(pos->first);
			pos++;
		}
		
		return keys;
	}
	
	BOOL contains(DWORD tid) {
		auto pos = db.find(tid);
		if (pos == db.end()) 
			return FALSE;
		return TRUE;
	}
	
	BOOL contains(DWORD tid, T bp) {
		if (!contains(tid))
			return FALSE;
		
		for (int i=0; i<db[tid].size(); i++) {
			if (db[tid][i] == bp) {
				return TRUE;
			}
		}
		
		return FALSE;	
	}
	
	BOOL contains(DWORD tid, DWORD64 addr) {
		if (!contains(tid))
			return FALSE;
		
		for (int i=0; i<db[tid].size(); i++) {
			if (db[tid][i]->get_address() == addr) {
				return TRUE;
			}
		}
		
		return FALSE;
	}
	
	vector<T>get_items(DWORD tid) {
		return db[tid];
	}
	
	T get_item_by_address(DWORD tid, DWORD64 address) {
		for (auto bp : db[tid])	{
			if (bp->get_address() == address) 
				return bp;
		}
		return NULL;
	}
	
	void insert(DWORD tid, T bp) {
		if (contains(tid)) {
			vector<T> vbp;
			db.insert( pair<DWORD, vector<T>>(tid, vbp) );
		}
		db[tid].push_back(bp);
	}
	
	void erase(DWORD tid) {
		for (int i=0; i<db[tid].size(); i++)
			delete db[tid][i];
		db.erase(tid);
	}
	
	void erase(DWORD tid, T bp) {
		for (int i=0; i<db[tid].size(); i++) {
			if (db[tid][i] == bp) { 
				delete db[tid][i];
				db[tid].erase(db[tid].begin()+i);
				break;
			}
		}
	}
	
	void clear() {
		for (auto key : get_keys()) {
			erase(key);
		}
	}
	
	void show() {
		auto pos = db.begin();
		while (pos != db.end()) {
			auto tid = pos->first;
			auto vecbp = pos->second;
			
			for (auto bp : vecbp) {				
				cout << tid << " ->  0x" << hex << bp->get_address() << endl;		
			}	
			pos++;
		}
	}
}; // end Box

template <typename T>
class Box2 {
private:
	map<pair<DWORD, DWORD64>, vector<T>> db;
	
public:
	map<pair<DWORD, DWORD64>, vector<T>> get_map() {
		return db;
	}
	
	vector<T> get_items(DWORD tid, DWORD64 addr) {
		return db[pair<DWORD, DWORD64>(tid, addr)];
	}
	
	BOOL contains(DWORD tid, DWORD64 addr) {
		auto pos = db.find(pair<DWORD, DWORD64>(tid, addr));
		if (pos == db.end()) 
			return FALSE;
		return TRUE;
	}
	
	void insert(DWORD tid, DWORD64 addr, T bp) {
		if (contains(tid, addr)) {
			vector<T> vbp;
			db.insert(make_pair(make_pair(tid,addr), vbp));
		}
		db[pair<DWORD,DWORD64>(tid,addr)].push_back(bp);
	}
	
	void erase(DWORD tid) {
		db.erase(tid);
	}
	
	void erase(DWORD tid, DWORD64 addr) {
		for (int i=0; i<db[make_pair(tid,addr)].size(); i++)
			delete db[make_pair(tid,addr)][i];
		db.erase(make_pair(tid,addr));
	}
	
	void erase(DWORD tid, DWORD64 addr, T bp) {
		for (int i=0; i<db[make_pair(tid,addr)].size(); i++) {
			if (db[make_pair(tid,addr)][i] == bp) { 
				delete db[make_pair(tid,addr)][i];
				db[make_pair(tid,addr)].erase(db[make_pair(tid,addr)].begin()+i);
				break;
			}
		}
	}
	
	void show() {
		auto pos = db.begin();
		while (pos != db.end()) {
			auto tid_addr = pos->first;
			auto vecbp = pos->second;
			
			for (auto bp : vecbp) {				
				cout << tid_addr->first << " " << tid_addr->second << " ->  0x" << hex << bp->get_address() << endl;		
			}	
			pos++;
		}
	}
	
}; // end Box2




