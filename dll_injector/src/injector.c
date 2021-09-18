#include "manualmap.h"
#include "injector.h"
#include <stdio.h>

int inject_LoadLibraryA(DWORD process_id, const char* dll)
{
    if (process_id == 0)
        return PROCESS_NOT_RUNNING;

    TCHAR full_dll_path[MAX_PATH];
    GetFullPathName(dll, MAX_PATH, full_dll_path, NULL);

    if (DllPathIsValid(full_dll_path) != 0)
        return DLL_DOES_NOT_EXIST;

    LPVOID load_library = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (load_library == NULL)
        return INJECTION_FAILED;

    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
    if (process_handle == NULL)
        return INJECTION_FAILED;

    // Allocate space to write the dll function
    LPVOID dll_parameter_address = VirtualAllocEx(process_handle, 0, strlen(full_dll_path), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (dll_parameter_address == NULL)
    {
        CloseHandle(process_handle);
        return INJECTION_FAILED;
    }

    BOOL wrote_memory = WriteProcessMemory(process_handle, dll_parameter_address, full_dll_path, strlen(full_dll_path), NULL);
    if (wrote_memory == false)
    {
        CloseHandle(process_handle);
        return INJECTION_FAILED;
    }

    HANDLE dll_thread_handle = CreateRemoteThread(process_handle, 0, 0, (LPTHREAD_START_ROUTINE)load_library, dll_parameter_address, 0, 0);
    if (dll_thread_handle == NULL)
    {
        CloseHandle(process_handle);
        return INJECTION_FAILED;
    }

    CloseHandle(dll_thread_handle);
    CloseHandle(process_handle);
    
    return 0;
}

int inject_ManualMap(DWORD process_id, const char* dll_path)
{
	loaderdata LoaderParams;

    TCHAR full_dll_path[MAX_PATH];
    GetFullPathName(dll_path, MAX_PATH, full_dll_path, NULL);
	LPCSTR Dll = full_dll_path;

	HANDLE hFile = CreateFileA(Dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, 0, NULL);

	DWORD FileSize = GetFileSize(hFile, NULL);
	PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + pDosHeader->e_lfanew);

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	
	PVOID ExecutableImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Copy the headers to target process
	WriteProcessMemory(hProcess, ExecutableImage, FileBuffer,
		pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// Target Dll's Section Header & copy sections of the dll to the target
	PIMAGE_SECTION_HEADER pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)ExecutableImage + pSectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
	}

	// Allocating memory for the loader code.
	PVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	LoaderParams.ImageBase = ExecutableImage;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)ExecutableImage + pDosHeader->e_lfanew);
	LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	LoaderParams.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)ExecutableImage
		+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	LoaderParams.fnLoadLibraryA = LoadLibraryA;
	LoaderParams.fnGetProcAddress = GetProcAddress;

	// Write the loader information to target process 
	WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata), NULL);
    WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader,
		(DWORD)stub - (DWORD)LibraryLoader, NULL);
    
	// Create a remote thread to execute the loader code
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1),
		LoaderMemory, 0, NULL);

	// Wait for the loader to finish executing
	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);

	return 0;
}

bool DllPathIsValid(TCHAR full_path[260])
{
    FILE* fp;
    if (fopen_s(&fp, TEXT(full_path), "r"))
        fclose(fp);
    else
        return false;

    return true;
}

void __handle_error(int inject_code)
{
    switch (inject_code)
    {
        case INCORRECT_PARAMETERS:
            fprintf(stdout, "Error code %d: Incorrect Paramters.\n", INCORRECT_PARAMETERS);
            break;
        case PROCESS_NOT_RUNNING:
            fprintf(stdout, "Error code %d: Process is not running.\n", PROCESS_NOT_RUNNING);
            break;
        case DLL_DOES_NOT_EXIST:
            fprintf(stdout, "Error code %d: DLL does not exist.\n", DLL_DOES_NOT_EXIST);
            break;
        case INJECTION_FAILED:
            fprintf(stdout, "Error code %d: Injection Failed.\n", DLL_DOES_NOT_EXIST);
            break;
        default:
            break;
    }
}

DWORD GetProcessIdByProcessName(const char* process_name)
{
    PROCESSENTRY32 process_entry = { 0 };
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE processes_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (Process32First(processes_snapshot, &process_entry))
    {
        do
        {
            if (strcmp(process_entry.szExeFile, process_name) == 0)
            {
                CloseHandle(processes_snapshot);
                return process_entry.th32ProcessID;
            }
        } while (Process32Next(processes_snapshot, &process_entry));
    }

    CloseHandle(processes_snapshot);
    return 0;
}
