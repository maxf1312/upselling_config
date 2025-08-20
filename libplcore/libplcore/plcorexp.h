#pragma once
#ifndef __PLCOREXP_H__
#define __PLCOREEXP_H__

#ifdef _WINDOWS
#  ifdef PLCORE_EXPORTS
#    define PLCORE_API __declspec(dllexport)
#  else
#    if defined(PLCORE_NOEXPORTS)
#      define PLCORE_API
#    else
#      define PLCORE_API __declspec(dllimport)
#    endif
#  endif
#else 
#  define PLCORE_API 
#endif // _WINDOWS

#endif // __PLCOREXP_H__
