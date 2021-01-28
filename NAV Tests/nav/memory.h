#pragma once

#include "winapi.h"

LPVOID NavAllocMem(SIZE_T SizeOfBlock);
LPVOID NavReAllocMem(LPVOID BlockAddress, SIZE_T NewSize);
BOOL NavFreeMem(LPVOID BlockAddress);