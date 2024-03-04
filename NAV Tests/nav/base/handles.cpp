#include "handles.h"

LPWSTR NAVAPI NavQueryProcessPathNameByHandle(
	IN HANDLE ProcessHandle) 
{
	DWORD PathSize = MAX_PATH + 1;
	LPWSTR PathBuffer = (LPWSTR)NavAllocate(PathSize * sizeof(WCHAR));
	if (PathBuffer == NULL) {
		NavFree(PathBuffer);
		return FALSE;
	}
	BOOL Status = QueryFullProcessImageNameW(ProcessHandle, NULL, PathBuffer, &PathSize);
	if (Status != FALSE) {
		return PathBuffer;
	}
	NavFree(PathBuffer);
	return NULL;
}

DWORD NAVAPI NavQueryProcessIdByHandle(
	IN HANDLE ProcessHandle) 
{
	return GetProcessId(ProcessHandle);
}

LPWSTR NAVAPI NavQueryKeyNameByHandle(
	IN HANDLE KeyHandle)
{
	ULONG KeyInfoBufferSize = 0;
	LPWSTR KeyPathName = NULL;

	NTSTATUS QueryStatus = NtQueryKey(KeyHandle, KEY_INFORMATION_CLASS::KeyNameInformation, 
		NULL, NULL, &KeyInfoBufferSize);
	
	if (QueryStatus == STATUS_BUFFER_TOO_SMALL) {
		KeyPathName = (LPWSTR)NavAllocate(KeyInfoBufferSize);
		if (KeyPathName == FALSE) {
			return FALSE;
		}
		QueryStatus = NtQueryKey(KeyHandle, KEY_INFORMATION_CLASS::KeyNameInformation,
			KeyPathName, KeyInfoBufferSize, &KeyInfoBufferSize);
	}

	if (QueryStatus == STATUS_SUCCESS) {
		return QUERY_KEY_BASE_TO_PATH(KeyPathName);
	}

	return FALSE;
}

LPWSTR NAVAPI NavQueryFileNameByHandle(
	IN HANDLE FileHandle) 
{
	DWORD dwPathSize = (DWORD)0x10;
	LPWSTR lpFileName = (LPWSTR)NavAllocate((dwPathSize + 1) * sizeof(WCHAR));

	ZeroMemory(lpFileName, (dwPathSize + 1) * sizeof(WCHAR));

	if (FileHandle == INVALID_HANDLE_VALUE) {
		NavFree(lpFileName);
		return FALSE;
	}

	DWORD Status = GetFinalPathNameByHandleW(FileHandle, lpFileName, dwPathSize, VOLUME_NAME_DOS);

	if (Status == FALSE) {
		NavFree(lpFileName);
		return FALSE;
	}

	if (Status > dwPathSize) {
		dwPathSize = (DWORD)Status;
		lpFileName = (LPWSTR)NavReAllocMem((LPVOID)lpFileName, (dwPathSize + 1) * sizeof(WCHAR));

		if (lpFileName == FALSE) {
			return FALSE;
		}

		ZeroMemory(lpFileName, (dwPathSize + 1) * sizeof(WCHAR));

		if (GetFinalPathNameByHandleW(FileHandle, lpFileName, dwPathSize, VOLUME_NAME_DOS) == FALSE) {
			NavFree(lpFileName);
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

BOOL NAVAPI NavQueryProcessHandles(
	IN ULONG ProcessId,
	IN PNAV_PROCESS_HANDLES ProcessHandles) 
{

	NTSTATUS Status;
	ULONG BufferSize = 0x20000;
	ULONG ReturnLength = 0;
	BOOLEAN IsFirstNode = TRUE;

	/*Fill buffer with zeros*/
	RtlZeroMemory((LPVOID)ProcessHandles, sizeof(NAV_PROCESS_HANDLES));

	/*Alloc initial buffer for retrieve system handles*/
	PSYSTEM_HANDLE_INFORMATION PtrHandleInformation = (PSYSTEM_HANDLE_INFORMATION)NavAllocate(BufferSize);

	/*Error while allocating memory*/
	if (PtrHandleInformation == NULL) {
		NavFree(PtrHandleInformation);
		return GetLastError();
	}

	/*Open target process to get his handle and duplicate
	all another handles associated to it*/
	HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ProcessId);

	/*Error while opening the process*/
	if (hProcess == NULL) {
		NavFree(PtrHandleInformation);
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
		NavFree(PtrHandleInformation);
		return GetLastError();
	}

	for (ULONG Idx = 0; Idx < PtrHandleInformation->HandleCount; Idx++)
	{
		HANDLE DuplicatedHandle;

		/*Duplicate the current handle of target process*/
		if (!NT_SUCCESS(NtDuplicateObject(hProcess, (HANDLE)PtrHandleInformation->Handles[Idx].Handle, GetCurrentProcess(), &DuplicatedHandle, 0, 0, 
			DUPLICATE_SAME_ACCESS))) {
			continue;
		}

		if (PtrHandleInformation->Handles[Idx].ProcessId != ProcessId) {
			continue;
		}

		HANDLE Handle = (HANDLE)PtrHandleInformation->Handles[Idx].Handle;
		ULONG QueryBufferSize = 0x50;
		ULONG RetriesCount = 0;
		BOOL QueryStatus = FALSE;
		POBJECT_TYPE_INFORMATION PtrObjectInformation = (POBJECT_TYPE_INFORMATION)NavAllocate(QueryBufferSize);

		/*Error while allocating memory*/
		if (PtrObjectInformation == NULL) {
			CloseHandle(hProcess);
			NavFree(PtrObjectInformation);
			NavFree(PtrHandleInformation);
			return GetLastError();
		}

		while (RetriesCount < 2) {
			if (!NT_SUCCESS(NtQueryObject(DuplicatedHandle, ObjectTypeInformation, PtrObjectInformation, QueryBufferSize, &QueryBufferSize))) {
				RetriesCount++;
				PtrObjectInformation = (POBJECT_TYPE_INFORMATION)NavReAllocMem(PtrObjectInformation, QueryBufferSize);
				/*Error while allocating memory*/
				if (PtrObjectInformation == NULL) {
					CloseHandle(hProcess);
					NavFree(PtrObjectInformation);
					NavFree(PtrHandleInformation);
					return GetLastError();
				}
			}
			else {
				QueryStatus = TRUE;
				break;
			}
		}

		if (QueryStatus == TRUE) {
			PNAV_PROCESS_HANDLES NavProcessHandlesNewEntry = (PNAV_PROCESS_HANDLES)NavAllocate(sizeof(NAV_PROCESS_HANDLES));

			NavProcessHandlesNewEntry->PObjectTypeInformation = PtrObjectInformation;
			NavProcessHandlesNewEntry->Handle = &Handle;
			NavProcessHandlesNewEntry->DuplicatedHandle = DuplicatedHandle;
			NavProcessHandlesNewEntry->NextAddress = NULL;

			PNAV_PROCESS_HANDLES NavCurrentProcessHandlesEntry = ProcessHandles;

			if (IsFirstNode == TRUE) {
				*NavCurrentProcessHandlesEntry = *NavProcessHandlesNewEntry;
				NavFree(NavProcessHandlesNewEntry);
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
			NavFree(PtrObjectInformation);
		}

	}

	CloseHandle(hProcess);
	NavFree(PtrHandleInformation);

	return TRUE;
}

BOOL NAVAPI NavFreeProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles) {
	PNAV_PROCESS_HANDLES TempStructHandles = ProcessHandles;
	PNAV_PROCESS_HANDLES LastStructHandles = ProcessHandles;

	ULONG NumOfStructElements = 1;

	BOOL Status = TRUE;

	while (TempStructHandles->NextAddress != NULL) {
		NumOfStructElements++;
		TempStructHandles = (PNAV_PROCESS_HANDLES)TempStructHandles->NextAddress;
	}

	TempStructHandles = ProcessHandles;

	for (ULONG Idx = 0; Idx < NumOfStructElements; Idx++) {
		LastStructHandles = TempStructHandles;
		TempStructHandles = (PNAV_PROCESS_HANDLES)TempStructHandles->NextAddress;
		NavFree(LastStructHandles->PObjectTypeInformation);
		ZeroMemory(LastStructHandles, sizeof(NAV_PROCESS_HANDLES));
		if ((NavFree(LastStructHandles) != TRUE) && (Status == TRUE)) {
			Status = FALSE;
		}
	}

	return Status;
}

BOOL NAVAPI NavQueryFilesByProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles,
	IN PNAV_PROCESS_OPEN_FILES ProcessFiles) 
{

	BOOL Status = FALSE;
	BOOL IsFirstNode = TRUE;
	PNAV_PROCESS_HANDLES CurrentHandleStruct = ProcessHandles;

	RtlZeroMemory(ProcessFiles, sizeof(NAV_PROCESS_OPEN_FILES));

	if (wcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"File") == 0) {
		LPWSTR lpFileName = NavQueryFileNameByHandle(CurrentHandleStruct->DuplicatedHandle);
		if (lpFileName != FALSE) {
			Status = TRUE;
			IsFirstNode = FALSE;
			PNAV_PROCESS_OPEN_FILES NavNewOpenFilesStruct =
				(PNAV_PROCESS_OPEN_FILES)NavAllocate(sizeof(NAV_PROCESS_OPEN_FILES));
			NavNewOpenFilesStruct->FilePathName = lpFileName;
			ProcessFiles->NextAddress = (LPVOID)NavNewOpenFilesStruct;
		}
	}

	while (CurrentHandleStruct->NextAddress != NULL) {
		if (wcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"File") != 0) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		LPWSTR lpFileName = NavQueryFileNameByHandle(CurrentHandleStruct->DuplicatedHandle);

		if (lpFileName == FALSE) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		Status = TRUE;

		PNAV_PROCESS_OPEN_FILES TempOpenFilesPointer = ProcessFiles;
		PNAV_PROCESS_OPEN_FILES NavNewOpenFilesStruct =
			(PNAV_PROCESS_OPEN_FILES)NavAllocate(sizeof(NAV_PROCESS_OPEN_FILES));

		NavNewOpenFilesStruct->FilePathName = lpFileName;
		NavNewOpenFilesStruct->NextAddress = NULL;

		if (IsFirstNode == TRUE) {
			IsFirstNode = FALSE;
			*TempOpenFilesPointer = *NavNewOpenFilesStruct;
			NavFree(NavNewOpenFilesStruct);
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

BOOL NAVAPI NavFreeOpenFiles(
	IN PNAV_PROCESS_OPEN_FILES ProcessFiles) 
{

	PNAV_PROCESS_OPEN_FILES TempFilesStruct = ProcessFiles;
	PNAV_PROCESS_OPEN_FILES LastFilesStruct = ProcessFiles;

	ULONG NumOfStructElements = 1;

	BOOL Status = TRUE;

	while (TempFilesStruct->NextAddress != NULL) {
		NumOfStructElements++;
		TempFilesStruct = (PNAV_PROCESS_OPEN_FILES)TempFilesStruct->NextAddress;
	}

	TempFilesStruct = ProcessFiles;

	for (ULONG Idx = 0; Idx < NumOfStructElements; Idx++) {

		LastFilesStruct = TempFilesStruct;
		TempFilesStruct = (PNAV_PROCESS_OPEN_FILES)TempFilesStruct->NextAddress;

		NavFree((LPVOID)(LastFilesStruct->FilePathName));

		ZeroMemory(LastFilesStruct, sizeof(NAV_PROCESS_OPEN_FILES));

		if ((NavFree(LastFilesStruct) != TRUE) && (Status == TRUE)) {
			Status = FALSE;
		}
	}

	return Status;
}

BOOL NAVAPI NavQueryKeysByProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles,
	IN PNAV_PROCESS_OPEN_KEYS ProcessKeys)
{
	BOOL Status = FALSE;
	BOOL IsFirstNode = TRUE;
	PNAV_PROCESS_HANDLES CurrentHandleStruct = ProcessHandles;

	RtlZeroMemory(ProcessKeys, sizeof(NAV_PROCESS_OPEN_KEYS));

	if (wcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"Key") == 0) {
		LPWSTR KeyPathName = NavQueryKeyNameByHandle(CurrentHandleStruct->DuplicatedHandle);
		if (KeyPathName != NULL) {
			Status = TRUE;
			IsFirstNode = FALSE;
			PNAV_PROCESS_OPEN_KEYS NavNewOpenKeysStruct =
				(PNAV_PROCESS_OPEN_KEYS)NavAllocate(sizeof(NAV_PROCESS_OPEN_KEYS));
			NavNewOpenKeysStruct->KeyPathName = KeyPathName;
			ProcessKeys->NextAddress = (LPVOID)NavNewOpenKeysStruct;
		}
	}

	while (CurrentHandleStruct->NextAddress != NULL) {
		if (wcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"Key") != 0) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		LPWSTR KeyPathName = NavQueryKeyNameByHandle(CurrentHandleStruct->DuplicatedHandle);

		if (KeyPathName == NULL) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		Status = TRUE;

		PNAV_PROCESS_OPEN_KEYS TempOpenKeysPointer = ProcessKeys;
		PNAV_PROCESS_OPEN_KEYS NavNewOpenKeysStruct =
			(PNAV_PROCESS_OPEN_KEYS)NavAllocate(sizeof(NAV_PROCESS_OPEN_KEYS));

		NavNewOpenKeysStruct->KeyPathName = KeyPathName;
		NavNewOpenKeysStruct->NextAddress = NULL;

		if (IsFirstNode == TRUE) {
			IsFirstNode = FALSE;
			*TempOpenKeysPointer = *NavNewOpenKeysStruct;
			NavFree(NavNewOpenKeysStruct);
		}
		else {
			while (TempOpenKeysPointer->NextAddress != NULL) {
				TempOpenKeysPointer = (PNAV_PROCESS_OPEN_KEYS)TempOpenKeysPointer->NextAddress;
			}
			TempOpenKeysPointer->NextAddress = (LPVOID)NavNewOpenKeysStruct;
		}

		CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
	}

	return Status;
}

BOOL NAVAPI NavFreeOpenKeys(
	IN PNAV_PROCESS_OPEN_KEYS ProcessKeys) 
{

	PNAV_PROCESS_OPEN_KEYS TempKeysStruct = ProcessKeys;
	PNAV_PROCESS_OPEN_KEYS LastKeysStruct = ProcessKeys;

	ULONG NumOfStructElements = 1;

	BOOL Status = TRUE;

	while (TempKeysStruct->NextAddress != NULL) {
		NumOfStructElements++;
		TempKeysStruct = (PNAV_PROCESS_OPEN_KEYS)TempKeysStruct->NextAddress;
	}

	TempKeysStruct = ProcessKeys;

	for (ULONG Idx = 0; Idx < NumOfStructElements; Idx++) {

		LastKeysStruct = TempKeysStruct;
		TempKeysStruct = (PNAV_PROCESS_OPEN_KEYS)TempKeysStruct->NextAddress;

		NavFree(QUERY_KEY_PATH_TO_BASE(LastKeysStruct->KeyPathName));

		ZeroMemory(LastKeysStruct, sizeof(NAV_PROCESS_OPEN_KEYS));

		if ((NavFree(LastKeysStruct) != TRUE) && (Status == TRUE)) {
			Status = FALSE;
		}
	}

	return Status;
}

BOOL NAVAPI NavQueryProcessesByProcessHandles(
	IN PNAV_PROCESS_HANDLES ProcessHandles,
	IN PNAV_PROCESS_OPEN_PROCESSES ProcessBuffer)
{
	BOOL Status = FALSE;
	BOOL IsFirstNode = TRUE;
	PNAV_PROCESS_HANDLES CurrentHandleStruct = ProcessHandles;

	RtlZeroMemory(ProcessBuffer, sizeof(NAV_PROCESS_OPEN_PROCESSES));

	if (wcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"Process") == 0) {
		LPWSTR FilePathName = NavQueryKeyNameByHandle(CurrentHandleStruct->DuplicatedHandle);
		if (FilePathName != NULL) {
			Status = TRUE;
			IsFirstNode = FALSE;
			PNAV_PROCESS_OPEN_PROCESSES NavNewOpenProcessesStruct =
				(PNAV_PROCESS_OPEN_PROCESSES)NavAllocate(sizeof(NAV_PROCESS_OPEN_PROCESSES));
			NavNewOpenProcessesStruct->FilePathName = FilePathName;
			ProcessBuffer->NextAddress = (LPVOID)NavNewOpenProcessesStruct;
		}
	}

	while (CurrentHandleStruct->NextAddress != NULL) {
		if (wcscmp(CurrentHandleStruct->PObjectTypeInformation->Name.Buffer, L"Process") != 0) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		LPWSTR FilePathName = NavQueryProcessPathNameByHandle(CurrentHandleStruct->DuplicatedHandle);
		DWORD ProcessId		= NavQueryProcessIdByHandle(CurrentHandleStruct->DuplicatedHandle);

		if (FilePathName == NULL) {
			CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
			continue;
		}

		Status = TRUE;

		PNAV_PROCESS_OPEN_PROCESSES TempOpenProcessesPointer = ProcessBuffer;
		PNAV_PROCESS_OPEN_PROCESSES NavNewOpenProcessesStruct =
			(PNAV_PROCESS_OPEN_PROCESSES)NavAllocate(sizeof(NAV_PROCESS_OPEN_PROCESSES));

		NavNewOpenProcessesStruct->FilePathName = FilePathName;
		NavNewOpenProcessesStruct->ProcessId = ProcessId;
		NavNewOpenProcessesStruct->NextAddress = NULL;

		if (IsFirstNode == TRUE) {
			IsFirstNode = FALSE;
			*TempOpenProcessesPointer = *NavNewOpenProcessesStruct;
			NavFree(NavNewOpenProcessesStruct);
		}
		else {
			while (TempOpenProcessesPointer->NextAddress != NULL) {
				TempOpenProcessesPointer = (PNAV_PROCESS_OPEN_PROCESSES)TempOpenProcessesPointer->NextAddress;
			}
			TempOpenProcessesPointer->NextAddress = (LPVOID)NavNewOpenProcessesStruct;
		}

		CurrentHandleStruct = (PNAV_PROCESS_HANDLES)CurrentHandleStruct->NextAddress;
	}

	return Status;
}

BOOL NAVAPI NavFreeOpenProcesses(
	IN PNAV_PROCESS_OPEN_PROCESSES ProcessBuffer) 
{

	PNAV_PROCESS_OPEN_PROCESSES TempProcessesStruct = ProcessBuffer;
	PNAV_PROCESS_OPEN_PROCESSES LastProcessesStruct = ProcessBuffer;

	ULONG NumOfStructElements = 1;

	BOOL Status = TRUE;

	while (TempProcessesStruct->NextAddress != NULL) {
		NumOfStructElements++;
		TempProcessesStruct = (PNAV_PROCESS_OPEN_PROCESSES)TempProcessesStruct->NextAddress;
	}

	TempProcessesStruct = ProcessBuffer;

	for (ULONG Idx = 0; Idx < NumOfStructElements; Idx++) {
		LastProcessesStruct = TempProcessesStruct;
		TempProcessesStruct = (PNAV_PROCESS_OPEN_PROCESSES)TempProcessesStruct->NextAddress;

		NavFree((LPVOID)(LastProcessesStruct->FilePathName));

		ZeroMemory(LastProcessesStruct, sizeof(NAV_PROCESS_OPEN_PROCESSES));

		if ((NavFree(LastProcessesStruct) != TRUE) && (Status == TRUE)) {
			Status = FALSE;
		}
	}

	return Status;
}