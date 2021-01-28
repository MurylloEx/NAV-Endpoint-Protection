#pragma once

#include "winapi.h"
#include "memory.h"
#include <tchar.h>

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


/* NAV exported functions */
LPTSTR	NavQueryFileNameByHandle	(
	_In_ HANDLE FileHandle);

BOOL	NavGetProcessHandles		(
	_In_ ULONG ProcessId, 
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct);

BOOL	NavFreeProcessHandles		(
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct);

BOOL	NavGetFilesByProcessHandles(
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct,
	_In_ PNAV_PROCESS_OPEN_FILES lpNavProcessOpenFilesStruct);

BOOL	NavFreeOpenFiles(
	_In_ PNAV_PROCESS_OPEN_FILES lpNavProcessOpenFilesStruct);