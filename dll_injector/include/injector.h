#ifndef _INJECTOR_H
#define _INJECTOR_H

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
#endif

#define INCORRECT_PARAMETERS  0xFFFFFFFF
#define PROCESS_NOT_RUNNING   0x00000001
#define DLL_DOES_NOT_EXIST    0x00000002
#define INJECTION_FAILED      0x00000004

#include <windows.h>
#include <tlhelp32.h>
#include <stdbool.h>

DWORD GetProcessIdByProcessName(const char* process_name);

bool DllPathIsValid(TCHAR full_path[260]);

int inject_LoadLibraryA(DWORD process_id, const char* dll);

int inject_ManualMap(DWORD process_id, const char* dll_path);

void __handle_error(int error_code);

#endif /* _INJECTOR_H */
