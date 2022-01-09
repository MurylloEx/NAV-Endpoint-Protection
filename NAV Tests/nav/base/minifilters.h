#pragma once

#include "status.h"
#include "memory.h"
#include "winapi.h"
#include "wmi.h"
#include <shlwapi.h>

typedef enum class _NAV_FILESYSTEM_ACTION_TYPE {
	ACTION_CREATED,
	ACTION_CHANGED,
	ACTION_DELETED,
	ACTION_RENAMED,
	ACTION_UNKNOWN
} NAV_FILESYSTEM_ACTION_TYPE, *PNAV_FILESYSTEM_ACTION_TYPE;

typedef enum class _NAV_FILESYSTEM_FILE_TYPE {
	TYPE_FILE,
	TYPE_FOLDER,
	TYPE_DEVICE,
	TYPE_UNKNOWN
} NAV_FILESYSTEM_FILE_TYPE, *PNAV_FILESYSTEM_FILE_TYPE;

typedef struct _NAV_FILESYSTEM_FILE_DATA {
	LPWSTR SrcFileName;
	LPWSTR DstFileName;
} NAV_FILESYSTEM_FILE_DATA, *PNAV_FILESYSTEM_FILE_DATA;

typedef VOID(NAVAPI* PNAV_FILESYSTEM_FILTER_CALLBACK)(
	IN NAV_FILESYSTEM_FILE_DATA FileData,
	IN NAV_FILESYSTEM_ACTION_TYPE Action,
	IN NAV_FILESYSTEM_FILE_TYPE FileType);

typedef struct _NAV_FILESYSTEM_FILTER {
	DWORD ThreadId;
	HANDLE ThreadHandle;
	LPCWSTR FileName;
	DWORD FileAccess;
	DWORD FileShare;
	DWORD FlagsAndAttributes;
	DWORD BufferSize;
	DWORD NotifyChanges;
	BOOL WatchSubtrees;
	LPVOID Reserved;
	BOOL IsRegistered;
	HANDLE UnregisteredEventHandle;
	PNAV_FILESYSTEM_FILTER_CALLBACK FilterCallback;
} NAV_FILESYSTEM_FILTER, *PNAV_FILESYSTEM_FILTER;

typedef enum _NAV_PROCESS_NOTIFY_TYPE {
	TYPE_CREATION,
	TYPE_TERMINATION
} NAV_PROCESS_NOTIFY_TYPE, *PNAV_PROCESS_NOTIFY_TYPE;

typedef struct _NAV_PROCESS_DATA {
	DWORD ProcessId;
	DWORD ParentProcessId;
	UINT64 CreationTime;
	LPWSTR ProcessName;
} NAV_PROCESS_DATA, *PNAV_PROCESS_DATA;

typedef VOID (NAVAPI* PNAV_PROCESS_FILTER_CALLBACK)(
	IN NAV_PROCESS_DATA ProcessData,
	IN NAV_PROCESS_NOTIFY_TYPE NotifyType);

typedef struct _NAV_PROCESS_FILTER {
	IWbemLocator* LocatorCreation;
	IWbemServices* ServicesCreation;
	IUnsecuredApartment* UnsecuredApartmentCreation;
	IUnknown* StubUnknownCreation;
	IWbemObjectSink* ObjectSinkCreation;
	CNavWmiEventSink* EventSinkCreation;
	IWbemLocator* LocatorTermination;
	IWbemServices* ServicesTermination;
	IUnsecuredApartment* UnsecuredApartmentTermination;
	IUnknown* StubUnknownTermination;
	IWbemObjectSink* ObjectSinkTermination;
	CNavWmiEventSink* EventSinkTermination;
	PNAV_PROCESS_FILTER_CALLBACK FilterCallback;
} NAV_PROCESS_FILTER, *PNAV_PROCESS_FILTER;

typedef struct _NAV_PNP_DEVICE_DATA {
	LPWSTR DriveName;
	ULONG64 CreationTime;
} NAV_PNP_DEVICE_DATA, *PNAV_PNP_DEVICE_DATA;

typedef enum _NAV_PNP_DEVICE_NOTIFY_TYPE {
	TYPE_INSERT,
	TYPE_REMOVE
} NAV_PNP_DEVICE_NOTIFY_TYPE, *PNAV_PNP_DEVICE_NOTIFY_TYPE;

typedef VOID(NAVAPI* PNAV_PNP_DEVICE_FILTER_CALLBACK)(
	NAV_PNP_DEVICE_DATA DeviceData, 
	NAV_PNP_DEVICE_NOTIFY_TYPE NotifyType);

typedef struct _NAV_PNP_DEVICE_FILTER {
	IWbemLocator* LocatorInserted;
	IWbemServices* ServicesInserted;
	IUnsecuredApartment* UnsecuredApartmentInserted;
	IUnknown* StubUnknownInserted;
	IWbemObjectSink* ObjectSinkInserted;
	CNavWmiEventSink* EventSinkInserted;
	IWbemLocator* LocatorRemoved;
	IWbemServices* ServicesRemoved;
	IUnsecuredApartment* UnsecuredApartmentRemoved;
	IUnknown* StubUnknownRemoved;
	IWbemObjectSink* ObjectSinkRemoved;
	CNavWmiEventSink* EventSinkRemoved;
	PNAV_PNP_DEVICE_FILTER_CALLBACK FilterCallback;
} NAV_PNP_DEVICE_FILTER, *PNAV_PNP_DEVICE_FILTER;

LPWSTR NAVAPI NavNormalizeFileNotifyPath(
	IN FILE_NOTIFY_INFORMATION *FileNotify,
	IN LPCWSTR BaseFileName);

NAV_FILESYSTEM_FILE_TYPE NAVAPI NavCheckFileType(
	IN LPCWSTR TargetPath);

NAVSTATUS NAVAPI NavRegisterFileSystemFilter(
	IN LPCWSTR FileName,
	IN DWORD FileAccess,
	IN DWORD FileShare,
	IN DWORD FlagsAndAttributes,
	IN DWORD BufferSize,
	IN DWORD NotifyChanges,
	IN BOOL WatchSubtrees,
	IN PNAV_FILESYSTEM_FILTER_CALLBACK FilterCallback,
	OUT PNAV_FILESYSTEM_FILTER* FilesystemFilter);

NAVSTATUS NAVAPI NavUnregisterFileSystemFilter(
	IN PNAV_FILESYSTEM_FILTER FilesystemFilter);

NAVSTATUS NAVAPI NavRegisterProcessFilter(
	IN PNAV_PROCESS_FILTER_CALLBACK FilterCallback,
	OUT PNAV_PROCESS_FILTER* ProcessFilter);

NAVSTATUS NAVAPI NavUnregisterProcessFilter(
	IN PNAV_PROCESS_FILTER ProcessFilter);

NAVSTATUS NAVAPI NavRegisterPnpDeviceFilter(
	IN PNAV_PNP_DEVICE_FILTER_CALLBACK FilterCallback,
	OUT PNAV_PNP_DEVICE_FILTER* DeviceFilter);