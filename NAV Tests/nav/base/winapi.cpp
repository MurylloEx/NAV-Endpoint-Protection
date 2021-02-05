#include "winapi.h"

FARPROC NavGetProcAddress(
	_In_ LPSTR LibraryName, 
	_In_ LPSTR FunctionName) 
{
	HMODULE LibraryHandle = GetModuleHandleA(LibraryName);
	if (LibraryHandle == NULL) {
		return NULL;
	}
	return GetProcAddress(LibraryHandle, FunctionName);
}

NTSTATUS NTAPI NtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	/*Load and retrieve the address of NtQuerySystemInformation API*/
	PNtQuerySystemInformation VNtQuerySystemInformation = 
		(PNtQuerySystemInformation)NavGetProcAddress(NTDLL, NtQuerySystemInformationName);

	return VNtQuerySystemInformation(
		SystemInformationClass, 
		SystemInformation, 
		SystemInformationLength, 
		ReturnLength);
}

NTSTATUS NTAPI NtDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options) 
{
	/*Load and retrieve the address of NtDuplicateObject API*/
	PNtDuplicateObject VNtDuplicateObject = (PNtDuplicateObject)NavGetProcAddress(NTDLL, NtDuplicateObjectName);

	return VNtDuplicateObject(
		SourceProcessHandle,
		SourceHandle,
		TargetProcessHandle,
		TargetHandle,
		DesiredAccess,
		Attributes,
		Options);
}

NTSTATUS NTAPI NtQueryObject(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength) 
{
	/*Load and retrieve the address of NtQueryObject API*/
	PNtQueryObject VNtQueryObject = (PNtQueryObject)NavGetProcAddress(NTDLL, NtQueryObjectName);

	return VNtQueryObject(
		ObjectHandle, 
		ObjectInformationClass, 
		ObjectInformation, 
		ObjectInformationLength, 
		ReturnLength);
}

NTSTATUS NTAPI NtQueryKey(
	HANDLE                KeyHandle,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength) 
{
	/*Load and retrieve the address of NtQueryKey API*/
	PNtQueryKey VNtQueryKey = (PNtQueryKey)NavGetProcAddress(NTDLL, NtQueryKeyName);

	return VNtQueryKey(
		KeyHandle, 
		KeyInformationClass, 
		KeyInformation, 
		Length, 
		ResultLength);
}

NTSTATUS NTAPI NtSetInformationProcess(
	HANDLE	ProcessHandle,
	ULONG	ProcessInformationClass,
	PVOID	ProcessInformation,
	ULONG	ProcessInformationLength)
{
	/*Load and retrieve the address of NtSetInformationProcess API*/
	PNtSetInformationProcess VNtSetInformationProcess = 
		(PNtSetInformationProcess)NavGetProcAddress(NTDLL, NtSetInformationProcessName);

	return VNtSetInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength);
}