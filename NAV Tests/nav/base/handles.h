#pragma once

#include "winapi.h"
#include "memory.h"
#include "status.h"

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
LPWSTR NAVAPI NavQueryProcessPathNameByHandle(
	IN HANDLE ProcessHandle);

DWORD NAVAPI NavQueryProcessIdByHandle(
	IN HANDLE ProcessHandle);

LPWSTR NAVAPI NavQueryKeyNameByHandle(
	IN HANDLE KeyHandle);

LPWSTR NAVAPI NavQueryFileNameByHandle(
	IN HANDLE FileHandle);

BOOL NAVAPI NavQueryProcessHandles(
	IN ULONG ProcessId,
	IN PNAV_PROCESS_HANDLES ProcessHandles);

BOOL NAVAPI NavFreeProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles);

BOOL NAVAPI NavQueryFilesByProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles,
	IN PNAV_PROCESS_OPEN_FILES ProcessFiles);

BOOL NAVAPI NavFreeOpenFiles(
	IN PNAV_PROCESS_OPEN_FILES ProcessFiles);

BOOL NAVAPI NavQueryKeysByProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles,
	IN PNAV_PROCESS_OPEN_KEYS ProcessKeys);

BOOL NAVAPI NavFreeOpenKeys(
	IN PNAV_PROCESS_OPEN_KEYS ProcessKeys);

BOOL NAVAPI NavQueryProcessesByProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles,
	IN PNAV_PROCESS_OPEN_PROCESSES ProcessBuffer);

BOOL NAVAPI NavFreeOpenProcesses(
	IN PNAV_PROCESS_OPEN_PROCESSES ProcessBuffer);