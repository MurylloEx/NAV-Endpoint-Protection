#pragma once

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")

//#define _WINSOCKAPI_ 
#include <Windows.h>
#include <iphlpapi.h>
#include <TlHelp32.h>

/* NT Functions and undocumented APIs */
#define NTDLL							(LPSTR)"NTDLL.DLL"
#define KERNEL32						(LPSTR)"KERNEL32.DLL"
#define ADVAPI32						(LPSTR)"ADVAPI32.DLL"
#define USER32							(LPSTR)"USER32.DLL"

#define NtQuerySystemInformationName	(LPSTR)"NtQuerySystemInformation"
#define NtDuplicateObjectName			(LPSTR)"NtDuplicateObject"
#define NtQueryObjectName				(LPSTR)"NtQueryObject"
#define NtQueryKeyName					(LPSTR)"NtQueryKey"
#define NtSetInformationProcessName		(LPSTR)"NtSetInformationProcess"

/* NTSTATUS Macros */
#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x) >= 0)
#endif

/* NTSTATUS Error Codes */
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

/* NT API Constants */
#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define NT_CRITICAL_PROCESS 0x1DUL

/* NT internal structures */
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

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation,
	KeyNodeInformation,
	KeyFullInformation,
	KeyNameInformation,
	KeyCachedInformation,
	KeyFlagsInformation,
	KeyVirtualizationInformation,
	KeyHandleTagsInformation,
	KeyTrustInformation,
	KeyLayerInformation,
	MaxKeyInfoClass
} KEY_INFORMATION_CLASS, *PKEY_INFORMATION_CLASS;

/* NT Types Definitions */
typedef LONG NTSTATUS, *PNTSTATUS;

/* NT API prototype functions */
typedef NTSTATUS(NTAPI *PNtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS(NTAPI *PNtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options);

typedef NTSTATUS(NTAPI *PNtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS(NTAPI *PNtQueryKey)(
	HANDLE                KeyHandle,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength);

typedef NTSTATUS(NTAPI *PNtSetInformationProcess)(
	HANDLE	ProcessHandle,
	ULONG	ProcessInformationClass,
	PVOID	ProcessInformation,
	ULONG	ProcessInformationLength);

/* NAV exported functions */
FARPROC NavGetProcAddress(_In_ LPSTR LibraryName, _In_ LPSTR FunctionName);

NTSTATUS NTAPI NtQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength);

NTSTATUS NTAPI NtDuplicateObject(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options);

NTSTATUS NTAPI NtQueryObject(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength);

NTSTATUS NTAPI NtQueryKey(
	HANDLE                KeyHandle,
	KEY_INFORMATION_CLASS KeyInformationClass,
	PVOID                 KeyInformation,
	ULONG                 Length,
	PULONG                ResultLength);

NTSTATUS NTAPI NtSetInformationProcess(
	HANDLE	ProcessHandle,
	ULONG	ProcessInformationClass,
	PVOID	ProcessInformation,
	ULONG	ProcessInformationLength);