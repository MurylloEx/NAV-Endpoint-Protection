#include "winapi.h"

FARPROC NavGetProcAddress(_In_ LPSTR LibraryName, _In_ LPSTR FunctionName) {
	return GetProcAddress(GetModuleHandleA(LibraryName), FunctionName);
}
