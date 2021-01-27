#include "memory.h"

LPVOID NavAllocMem(SIZE_T SizeOfBlock) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeOfBlock);
}

LPVOID NavReAllocMem(LPVOID BlockAddress, SIZE_T NewSize) {
	return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BlockAddress, NewSize);
}

BOOL NavFreeMem(LPVOID BlockAddress) {
	return HeapFree(GetProcessHeap(), NULL, BlockAddress);
}