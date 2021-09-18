#ifndef _MANUAL_MAP_H
#define _MANUAL_MAP_H

#include <windows.h>

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

typedef struct loaderdata
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

} loaderdata;

DWORD __stdcall LibraryLoader(LPVOID Memory);

DWORD __stdcall stub(void);

#endif /* _MANUAL_MAP_H */
