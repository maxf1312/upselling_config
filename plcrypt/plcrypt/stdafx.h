// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#ifndef _WIN32_WINNT		// Allow use of features specific to Windows XP or later.                   
#define _WIN32_WINNT 0x0501	// Change this to the appropriate value to target other versions of Windows.
#endif						

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#ifdef _WIN32
#include <windows.h>
#include <atlbase.h>
#endif // _WIN32

#include <memory>
#include <cwchar>
#include <vector>
#include <string>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <locale>
#include <algorithm>
#include <functional>
#include <list>




