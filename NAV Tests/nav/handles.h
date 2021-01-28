#pragma once

#include "winapi.h"
#include "memory.h"
#include <tchar.h>

/* NAV Handles Structures */
typedef struct _NAV_PROCESS_HANDLES {
	POBJECT_TYPE_INFORMATION PObjectTypeInformation;
	PHANDLE Handle;
	HANDLE DuplicatedHandle;
	LPVOID NextAddress;
} NAV_PROCESS_HANDLES, *PNAV_PROCESS_HANDLES;

typedef struct _NAV_PROCESS_OPEN_FILES {
	LPTSTR FilePathName;
	LPVOID NextAddress;
} NAV_PROCESS_OPEN_FILES, *PNAV_PROCESS_OPEN_FILES;

typedef struct _NAV_PROCESS_OPEN_KEYS {
	LPWSTR KeyPathName;
	LPVOID NextAddress;
} NAV_PROCESS_OPEN_KEYS, *PNAV_PROCESS_OPEN_KEYS;

/* NAV Macros definitions for NtQueryKey translations */
#define QUERY_KEY_BASE_TO_PATH(P) ((LPWSTR)((ULONG_PTR)P + (2 * sizeof(WCHAR))))
#define QUERY_KEY_PATH_TO_PATH(P) ((LPVOID)((ULONG_PTR)P - (2 * sizeof(WCHAR))))

/* NAV exported functions */
LPTSTR NavQueryKeyNameByHandle(
	_In_ HANDLE KeyHandle);

LPTSTR NavQueryFileNameByHandle (
	_In_ HANDLE FileHandle);

BOOL NavGetProcessHandles (
	_In_ ULONG ProcessId, 
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct);

BOOL NavFreeProcessHandles (
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct);

BOOL NavGetFilesByProcessHandles (
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct,
	_In_ PNAV_PROCESS_OPEN_FILES lpNavProcessOpenFilesStruct);

BOOL NavFreeOpenFiles (
	_In_ PNAV_PROCESS_OPEN_FILES lpNavProcessOpenFilesStruct);

BOOL NavGetKeysByProcessHandles(
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct,
	_In_ PNAV_PROCESS_OPEN_KEYS lpNavProcessOpenKeysStruct);