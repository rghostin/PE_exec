#include "winutils.h"

bool isOrdinalImport(DWORD IDesc) {
	return (IDesc & IMAGE_ORDINAL_FLAG32) != NULL;
}


DWORD getSectionProtectionFlag(DWORD sc) {
	// get default section protection given protection flag from section image_section_header[i].characteristics
	DWORD dwResult = 0;
	if (sc & IMAGE_SCN_MEM_NOT_CACHED)
		dwResult |= PAGE_NOCACHE;

	if (sc & IMAGE_SCN_MEM_EXECUTE) {
		if (sc & IMAGE_SCN_MEM_READ) {
			if (sc & IMAGE_SCN_MEM_WRITE)
				dwResult |= PAGE_EXECUTE_READWRITE;
			else
				dwResult |= PAGE_EXECUTE_READ;
		}
		else {
			if (sc & IMAGE_SCN_MEM_WRITE)
				dwResult |= PAGE_EXECUTE_WRITECOPY;
			else
				dwResult |= PAGE_EXECUTE;
		}
	}
	else {
		if (sc & IMAGE_SCN_MEM_READ) {
			if (sc & IMAGE_SCN_MEM_WRITE)
				dwResult |= PAGE_READWRITE;
			else
				dwResult |= PAGE_READONLY;
		}
		else {
			if (sc & IMAGE_SCN_MEM_WRITE)
				dwResult |= PAGE_WRITECOPY;
			else
				dwResult |= PAGE_NOACCESS;
		}
	}
	return dwResult;
}
