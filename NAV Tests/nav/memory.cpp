#include "memory.h"

#include <iostream>

LPVOID NavAllocMem(IN SIZE_T SizeOfBlock) {
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SizeOfBlock);
}

LPVOID NavReAllocMem(IN LPVOID BlockAddress, IN SIZE_T NewSize) {
	return HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BlockAddress, NewSize);
}

BOOL NavFreeMem(IN LPVOID BlockAddress) {
	return HeapFree(GetProcessHeap(), NULL, BlockAddress);
}
