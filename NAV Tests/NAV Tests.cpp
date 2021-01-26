// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>
#include <windows.h>

#pragma comment(lib, "ntdll.lib")

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS (NTAPI *PNtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

typedef NTSTATUS (NTAPI *PNtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
);

typedef NTSTATUS (NTAPI *PNtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
);

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE {
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE {
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION {
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFO {
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _NAV_PROCESS_HANDLES {
	POBJECT_TYPE_INFORMATION PObjectTypeInformation;
	PSYSTEM_HANDLE Handle;
	LPVOID NextAddress;
} NAV_PROCESS_HANDLES, *PNAV_PROCESS_HANDLES;

LPVOID NavGetFunctionPtr(_In_ LPSTR LibraryName, _In_ LPSTR FunctionName) {
	HMODULE LibraryHandle = GetModuleHandleA(LibraryName);
	return GetProcAddress(LibraryHandle, FunctionName);
}

BOOL NavGetProcessHandles(_In_ ULONG ProcessId, _Out_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct) {
	PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)NavGetFunctionPtr(
		(LPSTR)"NTDLL.DLL", 
		(LPSTR)"NtQuerySystemInformation"
	);

	PNtDuplicateObject NtDuplicateObject = (PNtDuplicateObject)NavGetFunctionPtr(
		(LPSTR)"NTDLL.DLL", 
		(LPSTR)"NtDuplicateObject"
	);

	PNtQueryObject NtQueryObject = (PNtQueryObject)NavGetFunctionPtr(
		(LPSTR)"NTDLL.DLL", 
		(LPSTR)"NtQueryObject"
	);

	NTSTATUS Status;
	ULONG BufferSize = 0x20000;
	ULONG ReturnLength = 0;

	PSYSTEM_HANDLE_INFORMATION PtrHandleInformation =
		(PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)BufferSize);

	/*Error while allocating memory*/
	if (PtrHandleInformation == NULL) {
		return GetLastError();
	}

	HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ProcessId);

	/*Error while opening the process*/
	if (hProcess == NULL) {
		return GetLastError();
	}

	while (Status = NtQuerySystemInformation(
		SystemHandleInformation,
		PtrHandleInformation,
		BufferSize, &BufferSize
	) == STATUS_INFO_LENGTH_MISMATCH) {
		BufferSize += 0x1000;
		PtrHandleInformation = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(
			GetProcessHeap(), HEAP_ZERO_MEMORY, PtrHandleInformation, (SIZE_T)BufferSize
		);
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
		POBJECT_TYPE_INFORMATION PtrObjectInformation = (POBJECT_TYPE_INFORMATION)HeapAlloc(
			GetProcessHeap(), HEAP_ZERO_MEMORY, QueryBufferSize);

		/*Error while allocating memory*/
		if (PtrObjectInformation == NULL) {
			return GetLastError();
		}

		if (Handle.ProcessId != ProcessId)
			continue;

		if (!NT_SUCCESS(NtDuplicateObject(hProcess, (HANDLE)Handle.Handle, GetCurrentProcess(), &DuplicatedHandle, 0, 0, 0)))
			continue;

		while (RetriesCount < 15) {
			if (!NT_SUCCESS(NtQueryObject(DuplicatedHandle, ObjectTypeInformation, PtrObjectInformation, QueryBufferSize, &QueryBufferSize))) {
				RetriesCount++;
				PtrObjectInformation = (POBJECT_TYPE_INFORMATION)HeapReAlloc(
					GetProcessHeap(), HEAP_ZERO_MEMORY, PtrObjectInformation, QueryBufferSize);
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
			PNAV_PROCESS_HANDLES NavProcessHandlesNewEntry = (PNAV_PROCESS_HANDLES)HeapAlloc(
				GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(NAV_PROCESS_HANDLES));

			NavProcessHandlesNewEntry->Handle = &Handle;
			NavProcessHandlesNewEntry->PObjectTypeInformation = PtrObjectInformation;
			NavProcessHandlesNewEntry->NextAddress = NULL;

			PNAV_PROCESS_HANDLES NavCurrentProcessHandlesEntry = lpNavProcessHandlesStruct;

			while (NavCurrentProcessHandlesEntry->NextAddress != NULL) {
				NavCurrentProcessHandlesEntry = (PNAV_PROCESS_HANDLES)NavCurrentProcessHandlesEntry->NextAddress;
			}
			
			NavCurrentProcessHandlesEntry->NextAddress = (LPVOID)NavProcessHandlesNewEntry;
		}

		CloseHandle(DuplicatedHandle);

	}

	CloseHandle(hProcess);
	HeapFree(GetProcessHeap(), NULL, PtrHandleInformation);

	return TRUE;
}

BOOL NavFreeProcessHandles(_In_ PNAV_PROCESS_HANDLES lpNavProcessHandlesStruct) {
	PNAV_PROCESS_HANDLES ptrTempNavStructHandles = lpNavProcessHandlesStruct;
	while (ptrTempNavStructHandles->NextAddress != NULL) {
		HeapFree(GetProcessHeap(), NULL, (LPVOID)ptrTempNavStructHandles->PObjectTypeInformation);
		ptrTempNavStructHandles = (PNAV_PROCESS_HANDLES)ptrTempNavStructHandles->NextAddress;
		HeapFree(GetProcessHeap(), NULL, (LPVOID)ptrTempNavStructHandles);
	}
	HeapFree(GetProcessHeap(), NULL, (LPVOID)ptrTempNavStructHandles);
	return TRUE;
}

int main()
{

	PNAV_PROCESS_HANDLES ptrNavHandles = (PNAV_PROCESS_HANDLES)HeapAlloc(
		GetProcessHeap(), NULL, sizeof(NAV_PROCESS_HANDLES));

	BOOL Status = NavGetProcessHandles(1464, ptrNavHandles);

	while (ptrNavHandles->NextAddress != NULL) {
		ptrNavHandles = (PNAV_PROCESS_HANDLES)ptrNavHandles->NextAddress;
		std::wcout << ptrNavHandles->PObjectTypeInformation->Name.Buffer << std::endl;
	}

	getchar();
	return ERROR_SUCCESS;
}

