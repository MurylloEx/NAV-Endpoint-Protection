#include "hook.h"

BOOL NAVAPI NavHookRestoreAfterWith(VOID) {
	return DetourRestoreAfterWith();
}

BOOL NAVAPI NavHookTransactionBegin(VOID) {
	if (DetourTransactionBegin() == FALSE)
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavHookTransactionCommit(VOID) {
	if (DetourTransactionCommit() == FALSE)
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavHookUpdateThread(HANDLE hThread) {
	if (DetourUpdateThread(hThread) != NO_ERROR)
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavHookDetourAttachFunction(PVOID *ppTargetFunction, PVOID pDetourFunction) {
	if (DetourAttach(ppTargetFunction, pDetourFunction) != NO_ERROR)
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavHookDetourDetachFunction(PVOID *ppTargetFunction, PVOID pDetourFunction) {
	if (DetourDetach(ppTargetFunction, pDetourFunction) != NO_ERROR)
		return FALSE;
	return TRUE;
}