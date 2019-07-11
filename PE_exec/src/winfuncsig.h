#pragma once

#pragma once
/*
WINAPI functions signature definitions
*/

#include <Windows.h>


typedef bool (WINAPI* PWINMAIN) (HINSTANCE, HINSTANCE, LPSTR, int);
//typedef bool (WINAPI* PMAIN) (int, char**);

typedef BOOL(WINAPI* DllEntryProc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);


//// NT  - start

// NT detailed infortmation of process
typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

//// NT - end