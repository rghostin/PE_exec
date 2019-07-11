#pragma once
#include <cstdio>
#include <Windows.h>
#include "wstructs.h"
#include "winfuncsig.h"

/*
Utilities using the WINAPI
*/

#ifndef COUNT_RELOC_ENTRIES
// given block size return number of entries type:offset in relocation data
#define COUNT_RELOC_ENTRIES(dwBlockSize) (dwBlockSize - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BASE_RELOCATION_ENTRY)
#endif


bool isOrdinalImport(DWORD IDesc);

DWORD getSectionProtectionFlag(DWORD sc);


PPEB getRemotePEB(HANDLE hProc);