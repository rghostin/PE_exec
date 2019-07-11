//==============================================================================
// Minimalistic Windows PE loader to manually load a process in memory
// the pe_exec function is written in C, the rest is in C++
// Note: Only tested for x86 systems
//==============================================================================

#include <cstdio>
#include "winutils.h"
#include "winfuncsig.h"
#include "wstructs.h"

//for readRawFile
#include <vector>
#include <iterator>
#include <fstream>

#define MIN(a, b) ( ((a)<(b)) ? (a) : (b))

#define CERR(e){fprintf(stderr, "Error %d : %s\n", GetLastError(),e);}

#define CERR_FREE(e) { CERR(e); VirtualFree((PVOID)ImageBase, 0, MEM_RELEASE);}


void pe_exec(BYTE* PERawData) {
	PIMAGE_DOS_HEADER pDOS;
	PIMAGE_NT_HEADERS32 pNT32;
	PIMAGE_OPTIONAL_HEADER32 pOH32;
	PIMAGE_SECTION_HEADER pSH;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc;

	DWORD  ImageBase, SectionBase, Delta;
	DWORD oldProt, min_;

	pDOS = (PIMAGE_DOS_HEADER)PERawData;
	pNT32 = (PIMAGE_NT_HEADERS32)(PERawData + pDOS->e_lfanew);
	pOH32 = &pNT32->OptionalHeader;
	pSH = (PIMAGE_SECTION_HEADER)(pOH32 + 1);

	if (pOH32->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		return;
	}

	// trying to reserve memory to preferred base address
	printf("Allocating memory\n");
	ImageBase = (DWORD)VirtualAlloc((PVOID)pOH32->ImageBase, pOH32->SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
	if (!ImageBase) {
		// attempt fail - try reserve memory to OS given address - rebasing needed later
		ImageBase = (DWORD)VirtualAlloc(NULL, pOH32->SizeOfImage, MEM_RESERVE, PAGE_NOACCESS);
		if (!ImageBase) {
			CERR("Error allocating memory");
			return;
		}
		printf("allocated to custom address - rebasong needed\n");
	}
	else {
		printf("allocated to preferred base address\n");
	}
	Delta = ImageBase - pOH32->ImageBase;


	// Writing headers
	printf("Writing headers\n");
	SectionBase = (DWORD)VirtualAlloc((PVOID)ImageBase, pOH32->SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE);
	if (!SectionBase) {
		CERR_FREE("Error commiting memory for headers");
		return;
	}
	memcpy((PVOID)SectionBase, PERawData, pOH32->SizeOfHeaders);
	if (!VirtualProtect((PVOID)SectionBase, pOH32->SizeOfHeaders, PAGE_READONLY, &oldProt)) {
		CERR_FREE("Error protecting memory for headers");
		return;
	}

	//    Writing sections
	for (unsigned i = 0; i < pNT32->FileHeader.NumberOfSections; i++) {
		printf("Writing section %s \n", pSH[i].Name);
		SectionBase = (DWORD)VirtualAlloc((PVOID)((DWORD)ImageBase + pSH[i].VirtualAddress), pSH[i].Misc.VirtualSize, MEM_COMMIT, PAGE_READWRITE);
		if (!SectionBase) {
			CERR_FREE("Error allocating memory for section");
			return;
		}
		SectionBase = (DWORD)(ImageBase + pSH[i].VirtualAddress);
		min_ = MIN(pSH[i].SizeOfRawData, pSH[i].Misc.VirtualSize);
		memcpy((PVOID)SectionBase, PERawData + pSH[i].PointerToRawData, min_);
	}

	// relocating if needed
	if (Delta != 0) {
		PIMAGE_SECTION_HEADER pPlRelocHeader = NULL;
		DWORD dwPlRelocDataAddr, dwOffset = 0;
		IMAGE_DATA_DIRECTORY relocData;

		printf("Relocating\n");
		// finding reloc data
		const char* section_to_find = ".reloc";

		for (unsigned i = 0; pNT32->FileHeader.NumberOfSections; ++i) {
			if (memcmp(pSH[i].Name, section_to_find, strlen(section_to_find)) == 0) {
				pPlRelocHeader = &(pSH[i]);	// pPlImage->Sections+i
				break;
			}
		}
		if (!pPlRelocHeader) {
			CERR_FREE("Could not fins reloc section header");
			return;
		}

		dwPlRelocDataAddr = pPlRelocHeader->PointerToRawData;
		dwOffset = 0;
		relocData = pOH32->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		while (dwOffset < relocData.Size) {
			PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)& PERawData[dwPlRelocDataAddr + dwOffset];
			dwOffset += sizeof(BASE_RELOCATION_BLOCK);
			DWORD dwEntryCount = COUNT_RELOC_ENTRIES(pBlockheader->BlockSize);
			PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)& PERawData[dwPlRelocDataAddr + dwOffset];

			for (unsigned y = 0; y < dwEntryCount; ++y) {
				dwOffset += sizeof(BASE_RELOCATION_ENTRY);
				if (pBlocks[y].Type == 0) { continue; } //type is usually 3 -- HIGH/LOW
				DWORD addrTarget = ImageBase + pBlockheader->PageAddress + pBlocks[y].Offset;
				(*(PDWORD)addrTarget) += Delta;
			}
		}
	}


	printf("Fixing imports\n");
	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)ImageBase + pOH32->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	for (; pImportDesc->Name != 0; pImportDesc++) {
		char* libName = (PCHAR)((DWORD)ImageBase + pImportDesc->Name);
		char* importName;
		HMODULE hLibModule = LoadLibraryA(libName);
		if (!hLibModule) {
			CERR_FREE("Error loading library");
			return;
		}
		DWORD* pImport = NULL, * pAddress = NULL, ProcAddress;

		pAddress = (DWORD*)((DWORD)ImageBase + pImportDesc->FirstThunk);
		if (pImportDesc->TimeDateStamp == 0)
			pImport = (DWORD*)((DWORD)ImageBase + pImportDesc->FirstThunk);
		else
			pImport = (DWORD*)((DWORD)ImageBase + pImportDesc->OriginalFirstThunk);
		for (unsigned i = 0; pImport[i] != 0; i++) {
			if (isOrdinalImport(pImport[i])) {
				ProcAddress = (DWORD)GetProcAddress(hLibModule, (PCHAR)(pImport[i] & 0xFFFF));
			}
			else {
				importName = (PCHAR)((DWORD)ImageBase + (pImport[i]) + 2);
				ProcAddress = (DWORD)GetProcAddress(hLibModule, importName);
			}
			if (!ProcAddress) {
				CERR_FREE("Error getting proc address");
				return;
			}
			pAddress[i] = ProcAddress;
		}
	}

	//  set section protection
	printf("Setting memory protections\n");
	for (unsigned i = 0; i < pNT32->FileHeader.NumberOfSections; i++) {
		if (!VirtualProtect((PVOID)((DWORD)ImageBase + pSH[i].VirtualAddress), pSH[i].Misc.VirtualSize, getSectionProtectionFlag(pSH[i].Characteristics), &oldProt)) {
			CERR_FREE("Error protecting memory for section");
			return;
		}
	}


	//  calling entry
	printf("Calling entry point");
	if (!pOH32->AddressOfEntryPoint) {
		CERR_FREE("Invalid address of entry point");
		return;
	}
	PWINMAIN pWinMain = (PWINMAIN)((DWORD)ImageBase + pOH32->AddressOfEntryPoint);
	if (!pWinMain((HINSTANCE)ImageBase, NULL, 0, SW_SHOWNORMAL)) {
		CERR_FREE("Error executing entry point");
		return;
	}
}



std::vector<BYTE> ReadRawFile(char* filename) {
	std::ifstream ifs(filename, std::ios::binary);
	if (!ifs) 
		throw "Error opening file ";
	return std::vector<BYTE>(std::istreambuf_iterator<char>(ifs), {});
}


int main(int argc, char* argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage : PE_exec.exe payloadPE.exe");
		return 1;
	}
	std::vector<BYTE> PERawData = ReadRawFile(argv[1]);
	pe_exec(&PERawData[0]);
	return 0;
}