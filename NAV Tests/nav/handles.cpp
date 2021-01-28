#include "handles.h"

LPTSTR NavQueryFileNameByHandle(
	_In_ HANDLE FileHandle) {
	DWORD dwPathSize = (DWORD)0x10;
	LPTSTR lpFileName = (LPTSTR)NavAllocMem((dwPathSize + 1) * sizeof(TCHAR));

	ZeroMemory(lpFileName, (dwPathSize + 1) * sizeof(TCHAR));

	if (FileHandle == INVALID_HANDLE_VALUE)
		return FALSE;

	DWORD Status = GetFinalPathNameByHandle(FileHandle, lpFileName, dwPathSize, VOLUME_NAME_DOS);

	if (Status == FALSE)
		return FALSE;

	if (Status > dwPathSize) {
		dwPathSize = (DWORD)Status;
		lpFileName = (LPTSTR)(NavReAllocMem((LPVOID)lpFileName, (dwPathSize + 1) * sizeof(TCHAR)));

		if (lpFileName == FALSE) {
			return FALSE;
		}

		ZeroMemory(lpFileName, (dwPathSize + 1) * sizeof(TCHAR));

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

BOOL NavGetProcessHandles(
	_In_ ULONG ProcessId,
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct) {
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

	/*Fill buffer with zeros*/
	RtlZeroMemory((LPVOID)lpNavProcessHandlesStruct, sizeof(NAV_PROCESS_HANDLES));

	/*Alloc initial buffer for retrieve system handles*/
	PSYSTEM_HANDLE_INFORMATION PtrHandleInformation = (PSYSTEM_HANDLE_INFORMATION)NavAllocMem(BufferSize);

	/*Error while allocating memory*/
	if (PtrHandleInformation == NULL) {
		NavFreeMem(PtrHandleInformation);
		return GetLastError();
	}

	/*Open target process to get his handle and duplicate
	all another handles associated to it*/
	HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ProcessId);

	/*Error while opening the process*/
	if (hProcess == NULL) {
		NavFreeMem(PtrHandleInformation);
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
		CloseHandle(hProcess);
		NavFreeMem(PtrHandleInformation);
		return GetLastError();
	}

	for (ULONG Idx = 0; Idx < PtrHandleInformation->HandleCount; Idx++)
	{
		HANDLE DuplicatedHandle;

		/*Duplicate the current handle of target process*/
		if (!NT_SUCCESS(NtDuplicateObject(hProcess, (HANDLE)PtrHandleInformation->Handles[Idx].Handle, GetCurrentProcess(), &DuplicatedHandle, 0, 0, 0))) {
			continue;
		}

		if (PtrHandleInformation->Handles[Idx].ProcessId != ProcessId) {
			continue;
		}

		HANDLE Handle = (HANDLE)PtrHandleInformation->Handles[Idx].Handle;
		ULONG QueryBufferSize = 0x50;
		ULONG RetriesCount = 0;
		BOOL QueryStatus = FALSE;
		POBJECT_TYPE_INFORMATION PtrObjectInformation = (POBJECT_TYPE_INFORMATION)NavAllocMem(QueryBufferSize);

		/*Error while allocating memory*/
		if (PtrObjectInformation == NULL) {
			CloseHandle(hProcess);
			NavFreeMem(PtrObjectInformation);
			NavFreeMem(PtrHandleInformation);
			return GetLastError();
		}

		while (RetriesCount < 2) {
			if (!NT_SUCCESS(NtQueryObject(DuplicatedHandle, ObjectTypeInformation, PtrObjectInformation, QueryBufferSize, &QueryBufferSize))) {
				RetriesCount++;
				PtrObjectInformation = (POBJECT_TYPE_INFORMATION)NavReAllocMem(PtrObjectInformation, QueryBufferSize);
				/*Error while allocating memory*/
				if (PtrObjectInformation == NULL) {
					CloseHandle(hProcess);
					NavFreeMem(PtrObjectInformation);
					NavFreeMem(PtrHandleInformation);
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
				NavFreeMem(NavProcessHandlesNewEntry);
				IsFirstNode = FALSE;
			}
			else {
				while (NavCurrentProcessHandlesEntry->NextAddress != NULL) {
					NavCurrentProcessHandlesEntry = (PNAV_PROCESS_HANDLES)NavCurrentProcessHandlesEntry->NextAddress;
				}
				NavCurrentProcessHandlesEntry->NextAddress = (LPVOID)NavProcessHandlesNewEntry;
			}
		}
		else {
			NavFreeMem(PtrObjectInformation);
		}

	}

	CloseHandle(hProcess);
	NavFreeMem(PtrHandleInformation);

	return TRUE;
}

BOOL NavFreeProcessHandles(
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct) {
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
		LastStructHandles = TempStructHandles;
		TempStructHandles = (PNAV_PROCESS_HANDLES)TempStructHandles->NextAddress;
		NavFreeMem(LastStructHandles->PObjectTypeInformation);
		ZeroMemory(LastStructHandles, sizeof(NAV_PROCESS_HANDLES));
		if ((NavFreeMem(LastStructHandles) != TRUE) && (Status == TRUE)) {
			Status = FALSE;
		}
	}

	return Status;
}

BOOL NavGetFilesByProcessHandles(
	_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct,
	_In_ PNAV_PROCESS_OPEN_FILES lpNavProcessOpenFilesStruct) {

	BOOL Status = FALSE;
	BOOL IsFirstNode = TRUE;
	PNAV_PROCESS_HANDLES CurrentHandleStruct = lpNavProcessHandlesStruct;

	RtlZeroMemory(lpNavProcessOpenFilesStruct, sizeof(NAV_PROCESS_OPEN_FILES));

	if (_tcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"File") == 0) {
		LPTSTR lpFileName = NavQueryFileNameByHandle(CurrentHandleStruct->DuplicatedHandle);
		if (lpFileName != NULL) {
			Status = TRUE;
			IsFirstNode = FALSE;
			PNAV_PROCESS_OPEN_FILES NavNewOpenFilesStruct =
				(PNAV_PROCESS_OPEN_FILES)NavAllocMem(sizeof(NAV_PROCESS_OPEN_FILES));
			NavNewOpenFilesStruct->FilePathName = lpFileName;
			lpNavProcessOpenFilesStruct->NextAddress = (LPVOID)NavNewOpenFilesStruct;
		}
	}

	while (CurrentHandleStruct->NextAddress != NULL) {
		if (_tcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"File") != 0) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		LPTSTR lpFileName = NavQueryFileNameByHandle(CurrentHandleStruct->DuplicatedHandle);

		if (lpFileName == NULL) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		Status = TRUE;

		PNAV_PROCESS_OPEN_FILES TempOpenFilesPointer = lpNavProcessOpenFilesStruct;
		PNAV_PROCESS_OPEN_FILES NavNewOpenFilesStruct =
			(PNAV_PROCESS_OPEN_FILES)NavAllocMem(sizeof(NAV_PROCESS_OPEN_FILES));

		NavNewOpenFilesStruct->FilePathName = lpFileName;
		NavNewOpenFilesStruct->NextAddress = NULL;

		if (IsFirstNode == TRUE) {
			IsFirstNode = FALSE;
			*TempOpenFilesPointer = *NavNewOpenFilesStruct;
		}
		else {
			while (TempOpenFilesPointer->NextAddress != NULL) {
				TempOpenFilesPointer = (PNAV_PROCESS_OPEN_FILES)TempOpenFilesPointer->NextAddress;
			}
			TempOpenFilesPointer->NextAddress = (LPVOID)NavNewOpenFilesStruct;
		}

		CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
	}

	return Status;
}

BOOL NavFreeOpenFiles(
	_In_ PNAV_PROCESS_OPEN_FILES lpNavProcessOpenFilesStruct) {

	PNAV_PROCESS_OPEN_FILES TempFilesStruct = lpNavProcessOpenFilesStruct;
	PNAV_PROCESS_OPEN_FILES LastFilesStruct = lpNavProcessOpenFilesStruct;

	ULONG NumOfStructElements = 1;

	BOOL Status = TRUE;

	while (TempFilesStruct->NextAddress != NULL) {
		NumOfStructElements++;
		TempFilesStruct = (PNAV_PROCESS_OPEN_FILES)TempFilesStruct->NextAddress;
	}

	TempFilesStruct = lpNavProcessOpenFilesStruct;

	for (ULONG Idx = 0; Idx < NumOfStructElements; Idx++) {
		LastFilesStruct = TempFilesStruct;
		TempFilesStruct = (PNAV_PROCESS_OPEN_FILES)TempFilesStruct->NextAddress;
		NavFreeMem((LPVOID)(LastFilesStruct->FilePathName));
		ZeroMemory(LastFilesStruct, sizeof(NAV_PROCESS_OPEN_FILES));
		if ((NavFreeMem(LastFilesStruct) != TRUE) && (Status == TRUE)) {
			Status = FALSE;
		}
	}


	if ((NavFreeMem(TempFilesStruct) != TRUE) && (Status == TRUE)) {
		Status = FALSE;
	}

	return Status;
}