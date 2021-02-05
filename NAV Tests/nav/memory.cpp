#include "memory.h"

LPVOID NAVAPI NavAllocMem(IN SIZE_T SizeOfBlock) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeOfBlock);
}

LPVOID NAVAPI NavReAllocMem(IN LPVOID BlockAddress, IN SIZE_T NewSize) {
	if (BlockAddress == NULL)
		return FALSE;
	return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BlockAddress, NewSize);
}

BOOL NAVAPI NavFreeMem(IN LPVOID BlockAddress) {
	if (BlockAddress == NULL)
		return FALSE;
	return HeapFree(GetProcessHeap(), NULL, BlockAddress);
}
