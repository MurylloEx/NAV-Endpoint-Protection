#pragma once

#include "winapi.h"
#include "status.h"

LPVOID NAVAPI NavAllocate(IN SIZE_T SizeOfBlock);
LPVOID NAVAPI NavReAllocMem(IN LPVOID BlockAddress, IN SIZE_T NewSize);
BOOL NAVAPI NavFree(IN LPVOID BlockAddress);