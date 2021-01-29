#pragma once

#include <vld.h>
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
	LPWSTR FilePathName;
	LPVOID NextAddress;
} NAV_PROCESS_OPEN_FILES, *PNAV_PROCESS_OPEN_FILES;

typedef struct _NAV_PROCESS_OPEN_KEYS {
	LPWSTR KeyPathName;
	LPVOID NextAddress;
} NAV_PROCESS_OPEN_KEYS, *PNAV_PROCESS_OPEN_KEYS;

typedef struct _NAV_PROCESS_OPEN_PROCESSES {
	LPWSTR FilePathName;
	DWORD ProcessId;
	LPVOID NextAddress;
} NAV_PROCESS_OPEN_PROCESSES, *PNAV_PROCESS_OPEN_PROCESSES;

/* NAV Macros definitions for NtQueryKey translations */
#define QUERY_KEY_BASE_TO_PATH(P) ((LPWSTR)((ULONG_PTR)P + (2 * sizeof(WCHAR))))
#define QUERY_KEY_PATH_TO_BASE(P) ((LPVOID)((ULONG_PTR)P - (2 * sizeof(WCHAR))))

/* NAV exported functions */
LPWSTR NavQueryProcessPathNameByHandle(
	_In_ HANDLE ProcessHandle);

DWORD NavQueryProcessIdByHandle(
	_In_ HANDLE ProcessHandle);

LPWSTR NavQueryKeyNameByHandle(
	_In_ HANDLE KeyHandle);

LPWSTR NavQueryFileNameByHandle(
	_In_ HANDLE FileHandle);

BOOL NavGetProcessHandles(
	_In_ ULONG ProcessId,
	_In_ PNAV_PROCESS_HANDLES ProcessHandles);

BOOL NavFreeProcessHandles(
	_In_ PNAV_PROCESS_HANDLES ProcessHandles);

BOOL NavGetFilesByProcessHandles(
	_In_ PNAV_PROCESS_HANDLES ProcessHandles,
	_In_ PNAV_PROCESS_OPEN_FILES ProcessFiles);

BOOL NavFreeOpenFiles(
	_In_ PNAV_PROCESS_OPEN_FILES ProcessFiles);

BOOL NavGetKeysByProcessHandles(
	_In_ PNAV_PROCESS_HANDLES ProcessHandles,
	_In_ PNAV_PROCESS_OPEN_KEYS ProcessKeys);

BOOL NavFreeOpenKeys(
	_In_ PNAV_PROCESS_OPEN_KEYS ProcessKeys);

BOOL NavGetProcessesByProcessHandles(
	_In_ PNAV_PROCESS_HANDLES ProcessHandles,
	_In_ PNAV_PROCESS_OPEN_PROCESSES ProcessBuffer);

BOOL NavFreeOpenProcesses(
	_In_ PNAV_PROCESS_OPEN_PROCESSES ProcessBuffer);