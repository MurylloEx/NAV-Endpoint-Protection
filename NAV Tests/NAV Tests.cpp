// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>

#include "nav/handles.h"
#include "nav/memory.h"
#include "nav/winapi.h"

LPTSTR NavQueryFileNameByHandle(HANDLE FileHandle) {
	DWORD dwPathSize = 0x10 * sizeof(TCHAR);
	LPTSTR lpFileName = (LPTSTR)NavAllocMem(dwPathSize);

	ZeroMemory(lpFileName, dwPathSize);

	DWORD Status = GetFinalPathNameByHandle(FileHandle, lpFileName, dwPathSize, VOLUME_NAME_DOS);

	if (Status == FALSE)
		return FALSE;

	if (Status > dwPathSize) {
		dwPathSize = (Status + 1) * sizeof(TCHAR);

		lpFileName = (LPTSTR)NavReAllocMem(lpFileName, dwPathSize);

		if (lpFileName == FALSE) {
			return FALSE;
		}

		if (GetFinalPathNameByHandle(FileHandle, lpFileName, dwPathSize, VOLUME_NAME_DOS) == FALSE) {
			return FALSE;
		}
		else {
			return lpFileName;
		}
	}
	else {
		return lpFileName;
	}
}

BOOL NavGetProcessHandles(_In_ ULONG ProcessId, _Out_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct) {
	/*Load and retrieve the address of NtQuerySystemInformation API*/
	PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)NavGetProcAddress(NTDLL, NtQuerySystemInformationName);
	
	/*Load and retrieve the address of NtDuplicateObject API*/
	PNtDuplicateObject NtDuplicateObject = (PNtDuplicateObject)NavGetProcAddress(NTDLL, NtDuplicateObjectName);
	
	/*Load and retrieve the address of NtQueryObject API*/
	PNtQueryObject NtQueryObject = (PNtQueryObject)NavGetProcAddress(NTDLL, NtQueryObjectName);

	NTSTATUS Status;
	ULONG BufferSize = 0x20000;
	ULONG ReturnLength = 0;
	BOOLEAN IsFirstNode = TRUE;

	/*Alloc initial buffer for retrieve system handles*/
	PSYSTEM_HANDLE_INFORMATION PtrHandleInformation = (PSYSTEM_HANDLE_INFORMATION)NavAllocMem(BufferSize);

	/*Error while allocating memory*/
	if (PtrHandleInformation == NULL) {
		return GetLastError();
	}

	/*Open target process to get his handle and duplicate 
	all another handles associated to it*/
	HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ProcessId);

	/*Error while opening the process*/
	if (hProcess == NULL) {
		return GetLastError();
	}

	/*Call NtQuerySystemInformation to retrieve all system handles*/
	while (Status = NtQuerySystemInformation(
		SystemHandleInformation,
		PtrHandleInformation,
		BufferSize, &BufferSize
	) == STATUS_INFO_LENGTH_MISMATCH) {
		BufferSize += 0x1000;
		/*If the BufferSize wasn't enough, realloc all memory block with 
		additional size of 4096 bytes and try again*/
		PtrHandleInformation = (PSYSTEM_HANDLE_INFORMATION)NavReAllocMem(PtrHandleInformation, BufferSize);
	}

	/*Cannot retrieve Handle information of the target process*/
	if (!NT_SUCCESS(Status)) {
		return GetLastError();
	}

	RtlZeroMemory((LPVOID)lpNavProcessHandlesStruct, sizeof(NAV_PROCESS_HANDLES));

	for (ULONG Idx = 0; Idx < PtrHandleInformation->HandleCount; Idx++)
	{
		SYSTEM_HANDLE Handle = PtrHandleInformation->Handles[Idx];
		HANDLE DuplicatedHandle;
		ULONG QueryBufferSize = 0x50;
		ULONG RetriesCount = 0;
		BOOL QueryStatus = FALSE;
		POBJECT_TYPE_INFORMATION PtrObjectInformation = (POBJECT_TYPE_INFORMATION)NavAllocMem(QueryBufferSize);

		/*Error while allocating memory*/
		if (PtrObjectInformation == NULL) {
			return GetLastError();
		}

		if (Handle.ProcessId != ProcessId)
			continue;

		/*Duplicate the current handle of target process*/
		if (!NT_SUCCESS(NtDuplicateObject(hProcess, (HANDLE)Handle.Handle, GetCurrentProcess(), &DuplicatedHandle, 0, 0, 0)))
			continue;

		while (RetriesCount < 15) {
			if (!NT_SUCCESS(NtQueryObject(DuplicatedHandle, ObjectTypeInformation, PtrObjectInformation, QueryBufferSize, &QueryBufferSize))) {
				RetriesCount++;
				PtrObjectInformation = (POBJECT_TYPE_INFORMATION)NavReAllocMem(PtrObjectInformation, QueryBufferSize);
				/*Error while allocating memory*/
				if (PtrObjectInformation == NULL) {
					return GetLastError();
				}
			}
			else {
				QueryStatus = TRUE;
				break;
			}
		}

		if (QueryStatus == TRUE) {
			PNAV_PROCESS_HANDLES NavProcessHandlesNewEntry = (PNAV_PROCESS_HANDLES)NavAllocMem(sizeof(NAV_PROCESS_HANDLES));
			
			NavProcessHandlesNewEntry->PObjectTypeInformation = PtrObjectInformation;
			NavProcessHandlesNewEntry->Handle = &Handle;
			NavProcessHandlesNewEntry->DuplicatedHandle = DuplicatedHandle;
			NavProcessHandlesNewEntry->NextAddress = NULL;
			
			PNAV_PROCESS_HANDLES NavCurrentProcessHandlesEntry = lpNavProcessHandlesStruct;

			if (IsFirstNode == TRUE) {
				*NavCurrentProcessHandlesEntry = *NavProcessHandlesNewEntry;
				IsFirstNode = FALSE;
				NavFreeMem(NavProcessHandlesNewEntry);
			}
			else {
				while (NavCurrentProcessHandlesEntry->NextAddress != NULL) {
					NavCurrentProcessHandlesEntry = (PNAV_PROCESS_HANDLES)NavCurrentProcessHandlesEntry->NextAddress;
				}
				NavCurrentProcessHandlesEntry->NextAddress = (LPVOID)NavProcessHandlesNewEntry;
			}
		}

	}

	CloseHandle(hProcess);
	NavFreeMem(PtrHandleInformation);

	return TRUE;
}

BOOL NavFreeProcessHandles(_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct) {
	PNAV_PROCESS_HANDLES TempStructHandles = lpNavProcessHandlesStruct;
	PNAV_PROCESS_HANDLES LastStructHandles = lpNavProcessHandlesStruct;

	ULONG NumOfStructElements = 1;

	BOOL Status = TRUE;

	while (TempStructHandles->NextAddress != NULL) {
		NumOfStructElements++;
		TempStructHandles = (PNAV_PROCESS_HANDLES)TempStructHandles->NextAddress;
	}

	TempStructHandles = lpNavProcessHandlesStruct;

	for (ULONG Idx = 0; Idx < NumOfStructElements; Idx++) {
		ZeroMemory(LastStructHandles, sizeof(NAV_PROCESS_HANDLES));
		if ((NavFreeMem(LastStructHandles) != TRUE) && (Status == TRUE)) {
			Status = FALSE;
		}
		LastStructHandles = TempStructHandles;
		TempStructHandles = (PNAV_PROCESS_HANDLES)TempStructHandles->NextAddress;
	}

	if ((NavFreeMem(TempStructHandles) != TRUE) && (Status == TRUE)) {
		Status = FALSE;
	}

	return Status;
}

BOOL NavGetFilesByProcessHandles(_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct) {
	PNAV_PROCESS_HANDLES CurrentHandleStruct = lpNavProcessHandlesStruct;
	
	if (_tcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer , L"File") == 0) {
		//Found the first File handle
		printf("Found");
	}

	while (CurrentHandleStruct->NextAddress != NULL) {
		if (_tcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"File") != 0) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}
		//Found a file Handle
		LPTSTR lpFileName = NavQueryFileNameByHandle(CurrentHandleStruct->DuplicatedHandle);
		if (lpFileName == NULL) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}
		std::wcout << lpFileName << std::endl;
		CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
	}

	return TRUE;
}



int main()
{

	PNAV_PROCESS_HANDLES ptrNavHandles = (PNAV_PROCESS_HANDLES)NavAllocMem(sizeof(NAV_PROCESS_HANDLES));

	BOOL Status = NavGetProcessHandles(5768, ptrNavHandles);
	//BOOL NewStatus = NavFreeProcessHandles(ptrNavHandles);

	NavGetFilesByProcessHandles(ptrNavHandles);



	std::wcout << ptrNavHandles->PObjectTypeInformation->Name.Buffer << std::endl;

	while (ptrNavHandles->NextAddress != NULL) {
		ptrNavHandles = (PNAV_PROCESS_HANDLES)ptrNavHandles->NextAddress;
		std::wcout << ptrNavHandles->PObjectTypeInformation->Name.Buffer << std::endl;
	}



	getchar();
	return ERROR_SUCCESS;
}

