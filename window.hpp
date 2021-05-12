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

//// Window ////

class Window {
protected:
	HWND hWin;
public:
	Window(HWND hWin) {
		this->hWin = hWin;
	}
}; // end Window


