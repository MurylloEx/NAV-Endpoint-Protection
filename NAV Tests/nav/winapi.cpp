#include "winapi.h"

FARPROC NavGetProcAddress(_In_ LPSTR LibraryName, _In_ LPSTR FunctionName) {
	HMODULE LibraryHandle = GetModuleHandleA(LibraryName);
	if (LibraryHandle == NULL) {
		return NULL;
	}
	return GetProcAddress(LibraryHandle, FunctionName);
}
