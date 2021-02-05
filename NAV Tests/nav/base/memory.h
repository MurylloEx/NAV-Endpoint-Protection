#pragma once

#include "winapi.h"
#include "status.h"

LPVOID NavAllocMem(IN SIZE_T SizeOfBlock);
LPVOID NavReAllocMem(IN LPVOID BlockAddress, IN SIZE_T NewSize);
BOOL NavFreeMem(IN LPVOID BlockAddress);