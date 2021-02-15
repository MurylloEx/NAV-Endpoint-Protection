#pragma once

#include "winapi.h"
#include "status.h"

LPVOID NAVAPI NavAllocMem(IN SIZE_T SizeOfBlock);
LPVOID NAVAPI NavReAllocMem(IN LPVOID BlockAddress, IN SIZE_T NewSize);
BOOL NAVAPI NavFreeMem(IN LPVOID BlockAddress);