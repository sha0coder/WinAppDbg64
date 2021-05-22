/*
	WinAppDbg64
	@sha0coder
	
	Mario Vilas' WinAppDbg port to C++ 64bits
	
	COMPILER FLAGS:
		 -std=C++11
	
	LINKER FLAGS:
		-lpsapi 

*/

#include <string>

class Symbol {
public:
	std::string name;
	void *address;
	SIZE_T size;
	
	Symbol(std::string name, void *address, SIZE_T size) {
		this->name = name;
		this->address = address;
		this->size = size;
	}
	
	Symbol(char *name, void *address, SIZE_T size) {
		string str(name);
		this->name = str;
		this->address = address;
		this->size = size;
	}
};


