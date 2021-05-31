#pragma once

#include "winapi.h"
#include "status.h"
#include <detours.h>

BOOL NAVAPI NavHookRestoreAfterWith(VOID);
BOOL NAVAPI NavHookTransactionBegin(VOID);
BOOL NAVAPI NavHookTransactionCommit(VOID);
BOOL NAVAPI NavHookUpdateThread(HANDLE hThread);
BOOL NAVAPI NavHookDetourAttachFunction(PVOID *ppTargetFunction, PVOID pDetourFunction);
BOOL NAVAPI NavHookDetourDetachFunction(PVOID *ppTargetFunction, PVOID pDetourFunction);