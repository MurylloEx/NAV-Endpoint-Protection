#pragma once

#include "status.h"
#include <Windows.h>

NAVSTATUS NAVAPI NavInjectLoadLibraryRoutine(
	IN DWORD ProcessId,
	IN LPWSTR ModulePath,
	OUT HANDLE* ThreadHandle);

NAVSTATUS NAVAPI NavInjectGlobalModule(
	IN LPWSTR ModulePath,
	IN LPSTR Procedure,
	OUT HHOOK* HookHandle);