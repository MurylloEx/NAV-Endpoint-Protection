#include "memory.h"

#include <iostream>

LPVOID NavAllocMem(SIZE_T SizeOfBlock) {
	void* addr = malloc(SizeOfBlock);
	ZeroMemory(addr, SizeOfBlock);
	return addr;
	//return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeOfBlock);
}

LPVOID NavReAllocMem(LPVOID BlockAddress, SIZE_T NewSize) {
	void* addr = realloc(BlockAddress, NewSize);
	ZeroMemory(addr, NewSize);
	return addr;
	//return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BlockAddress, NewSize);
}

BOOL NavFreeMem(LPVOID BlockAddress) {
	free(BlockAddress);
	return TRUE;
	//return HeapFree(GetProcessHeap(), NULL, BlockAddress);
}
