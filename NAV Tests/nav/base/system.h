#pragma once

#include "winapi.h"
#include "status.h"

typedef struct _NAV_THREAD_INFORMATION {
	DWORD ProcessId;
	DWORD ThreadId;
	LPVOID NextOffset;
} NAV_THREAD_INFORMATION, *PNAV_THREAD_INFORMATION;

BOOL NAVAPI NavIsX64System();

BOOL NAVAPI NavIsX86System();

BOOL NAVAPI NavIsX64Process(DWORD ProcessId);

BOOL NAVAPI NavIsX86Process(DWORD ProcessId);

NAVSTATUS NAVAPI NavEnumProcessThreads(
	IN DWORD ProcessId,
	OUT PNAV_THREAD_INFORMATION* ThreadInformation,
	OUT LPDWORD NumberOfThreads);

NAVSTATUS NAVAPI NavReleaseEnumProcessThreads(
	IN PNAV_THREAD_INFORMATION ThreadInformation,
	IN DWORD NumberOfThreads);