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

#include "windows.h"
#include "util.hpp"
#include <sstream>


class Label {
public:
	string module;
	string function;
	DWORD offset;
	
	Label() {
		module = "";
		function = "";
		offset = 0;
	}
	
	Label(string module, string function, DWORD offset) {
		this->module = module;
		this->function = function;
		this->offset = offset;
	}
	
	static string parse_label(string module, string function, DWORD offset) {
		stringstream lbl;
		
		if (!module.empty())
			lbl << module;	
		lbl << "!";

		if (!function.empty()) {
			lbl << function;
			
			if (offset > 0)
				lbl << "+0x" << hex << offset;
			
		} else {
			if (offset > 0) 
				lbl << "0x" << hex << offset;
			else 
				lbl << "0x00";
		}
		
		return lbl.str();
	}
	
	static string parse_label(string module, string function, void *offset) {
		stringstream lbl;
		
		if (!module.empty())
			lbl << module;	
		lbl << "!";

		if (!function.empty()) {
			lbl << function;
			
			if (offset > 0)
				lbl << "+0x" << hex << offset;
			
		} else {
			if (offset > 0) 
				lbl << "0x" << hex << offset;
			else 
				lbl << "0x00";
		}
		
		return lbl.str();
	}
	
	static Label split_label_strict(string label) {
		Label lbl;
		SuperString ss(label);
		
		ss.replace_all("\t","");
		ss.replace_all("\r","");
		ss.replace_all("\n","");
		ss.replace_all(" ","");
		
		if (ss.empty()) 
			ss = "0x0";
		
		if (ss.contains("!")) {
			auto modfunc = ss.split('!');
			if (modfunc.size() != 2) {
				cout << "malformed label " << label << endl;
				return lbl;
			}
			
			SuperString mod(modfunc[0]);
			SuperString func(modfunc[1]);
			
			if (mod.contains("+")) {
				cout << "malformed label " << label << endl;
				return lbl;
			}
			
			lbl.module = modfunc[0];
			
			if (func.contains("+")) {
				auto funcoff = func.split('+');
				if (funcoff.size() != 2) {
					cout << "malformed label " << label << endl;
					return lbl;
				}
				
				lbl.function = funcoff[0];
				lbl.offset = atoi(funcoff[1].c_str());
			} else {
				lbl.function = modfunc[1];
			}
			
			
		} else {
			lbl.module = label;
		}
		
		return lbl;
	}
	
	static Label split_label_fuzzy(string label) {
		return Label::split_label_strict(label);
	}
	
	static Label split_label(string label) {
		return Label::split_label_strict(label);
	}

}; // end Label
