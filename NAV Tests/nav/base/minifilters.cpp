#include "minifilters.h"

LPWSTR NAVAPI NavNormalizeFileNotifyPath(
	IN FILE_NOTIFY_INFORMATION *FileNotify,
	IN LPCWSTR BaseFileName)
{
	LPWSTR RelFileName = new wchar_t[FileNotify->FileNameLength + sizeof(wchar_t)];
	ZeroMemory(RelFileName, FileNotify->FileNameLength + sizeof(wchar_t));
	CopyMemory(RelFileName, FileNotify->FileName, FileNotify->FileNameLength);

	INT BasePathSize = lstrlenW((LPCWSTR)BaseFileName);
	INT SubPathSize = lstrlenW((LPCWSTR)RelFileName);

	LPWSTR AbFileName = new wchar_t[BasePathSize + SubPathSize + sizeof(wchar_t)];
	ZeroMemory(AbFileName, BasePathSize + SubPathSize + sizeof(wchar_t));

	PathCombineW(AbFileName, BaseFileName, RelFileName);
	delete[] RelFileName;

	return AbFileName;
}

NAV_FILESYSTEM_FILE_TYPE NAVAPI NavCheckFileType(
	IN LPCWSTR TargetPath)
{
	DWORD Attributes = GetFileAttributesW(TargetPath);
	if (Attributes == INVALID_FILE_ATTRIBUTES) {
		return NAV_FILESYSTEM_FILE_TYPE::TYPE_UNKNOWN;
	}
	if ((Attributes & FILE_ATTRIBUTE_DEVICE) == FILE_ATTRIBUTE_DEVICE) {
		return NAV_FILESYSTEM_FILE_TYPE::TYPE_DEVICE;
	}
	if ((Attributes & FILE_ATTRIBUTE_DIRECTORY) == FILE_ATTRIBUTE_DIRECTORY) {
		return NAV_FILESYSTEM_FILE_TYPE::TYPE_FOLDER;
	}
	return NAV_FILESYSTEM_FILE_TYPE::TYPE_FILE;
}

DWORD WINAPI NavFileSystemFilterThread(LPVOID Params) {
	PNAV_FILESYSTEM_FILTER FsFilter = (PNAV_FILESYSTEM_FILTER)Params;
	HANDLE FileHandle = CreateFileW(FsFilter->FileName, FsFilter->FileAccess, FsFilter->FileShare,
		NULL, OPEN_EXISTING, FsFilter->FlagsAndAttributes, NULL);

	if (FileHandle == INVALID_HANDLE_VALUE) {
		return EXIT_FAILURE;
	}

	LPVOID Buffer = NavAllocMem(FsFilter->BufferSize);

	if (Buffer == NULL) {
		FsFilter->Reserved = NULL;
		return EXIT_FAILURE;
	}

	FsFilter->Reserved = Buffer;

	while (true) {
		DWORD NotifyOffset = 0;
		DWORD BytesReturned = 0;
		DWORD BytesTransferred = 0;
		OVERLAPPED Overlapped = { 0 };
		FILE_NOTIFY_INFORMATION *FileNotify = NULL;

		ZeroMemory(Buffer, FsFilter->BufferSize);

		Overlapped.hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);

		BOOL Status = ReadDirectoryChangesW(FileHandle, Buffer, FsFilter->BufferSize, FsFilter->WatchSubtrees,
			FsFilter->NotifyChanges, &BytesReturned, &Overlapped, NULL);

		if (Status == FALSE) {
			CloseHandle(Overlapped.hEvent);
			continue;
		}

		Status = GetOverlappedResult(FileHandle, &Overlapped, &BytesTransferred, FALSE);

		if (Status == FALSE) {
			CloseHandle(Overlapped.hEvent);
			continue;
		}

		if (WaitForSingleObject(Overlapped.hEvent, 0) != WAIT_OBJECT_0) {
			CloseHandle(Overlapped.hEvent);
			continue;
		}

		ResetEvent(Overlapped.hEvent);

		do {
			FileNotify = (FILE_NOTIFY_INFORMATION*)((ULONG_PTR)Buffer + NotifyOffset);

			if (FileNotify->Action == FILE_ACTION_RENAMED_NEW_NAME) {
				NotifyOffset += FileNotify->NextEntryOffset;
				continue;
			}

			NAV_FILESYSTEM_ACTION_TYPE Action = NAV_FILESYSTEM_ACTION_TYPE::ACTION_UNKNOWN;
			NAV_FILESYSTEM_FILE_TYPE Type = NAV_FILESYSTEM_FILE_TYPE::TYPE_UNKNOWN;
			NAV_FILESYSTEM_FILE_DATA FileData = { 0 };

			FileData.SrcFileName = NavNormalizeFileNotifyPath(FileNotify, FsFilter->FileName);

			if (FileNotify->Action == FILE_ACTION_ADDED) {
				Action = NAV_FILESYSTEM_ACTION_TYPE::ACTION_CREATED;
			}
			else if (FileNotify->Action == FILE_ACTION_REMOVED) {
				Action = NAV_FILESYSTEM_ACTION_TYPE::ACTION_DELETED;
			}
			else if (FileNotify->Action == FILE_ACTION_MODIFIED) {
				Action = NAV_FILESYSTEM_ACTION_TYPE::ACTION_CHANGED;
			}
			else if (FileNotify->Action == FILE_ACTION_RENAMED_OLD_NAME) {
				Action = NAV_FILESYSTEM_ACTION_TYPE::ACTION_RENAMED;
			}

			if ((Action == NAV_FILESYSTEM_ACTION_TYPE::ACTION_RENAMED) && (FileNotify->NextEntryOffset != NULL)) {
				FILE_NOTIFY_INFORMATION* FsNextInfo = (FILE_NOTIFY_INFORMATION*)((ULONG_PTR)Buffer + NotifyOffset + FileNotify->NextEntryOffset);
				if (FsNextInfo->Action == FILE_ACTION_RENAMED_NEW_NAME) {
					FileData.DstFileName = NavNormalizeFileNotifyPath(FsNextInfo, FsFilter->FileName);
					Type = NavCheckFileType((LPCWSTR)FsFilter->FileName);
				}
			}

			if ((Action != NAV_FILESYSTEM_ACTION_TYPE::ACTION_RENAMED) &&
				(Action != NAV_FILESYSTEM_ACTION_TYPE::ACTION_DELETED))
				Type = NavCheckFileType((LPCWSTR)FileData.SrcFileName);

			FsFilter->FilterCallback(FileData, Action, Type);

			delete[] FileData.SrcFileName;

			if (FileData.DstFileName != NULL)
				delete[] FileData.DstFileName;

			NotifyOffset += FileNotify->NextEntryOffset;
		} while (FileNotify->NextEntryOffset != NULL);
	}
}

NAVSTATUS NAVAPI NavRegisterFileSystemFilter(
	IN LPCWSTR FileName,
	IN DWORD FileAccess,
	IN DWORD FileShare,
	IN DWORD FlagsAndAttributes,
	IN DWORD BufferSize,
	IN DWORD NotifyChanges,
	IN BOOL WatchSubtrees,
	IN PNAV_FILESYSTEM_FILTER_CALLBACK FilterCallback,
	OUT PNAV_FILESYSTEM_FILTER* FilesystemFilter)
{
	PNAV_FILESYSTEM_FILTER FsFilter = (PNAV_FILESYSTEM_FILTER)NavAllocMem(sizeof(NAV_FILESYSTEM_FILTER));

	if (FsFilter == NULL) {
		return NAV_REGISTER_FS_FILTER_STATUS_FAILED;
	}

	FsFilter->FileName = FileName;
	FsFilter->FileAccess = FileAccess;
	FsFilter->FileShare = FileShare;
	FsFilter->FlagsAndAttributes = FlagsAndAttributes;
	FsFilter->BufferSize = BufferSize;
	FsFilter->NotifyChanges = NotifyChanges;
	FsFilter->WatchSubtrees = WatchSubtrees;
	FsFilter->FilterCallback = FilterCallback;

	if ((FsFilter->FlagsAndAttributes & FILE_FLAG_OVERLAPPED) == FILE_FLAG_OVERLAPPED)
		FsFilter->FlagsAndAttributes = FsFilter->FlagsAndAttributes & ~FILE_FLAG_OVERLAPPED;

	FsFilter->ThreadHandle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)NavFileSystemFilterThread,
		FsFilter, NULL, &FsFilter->ThreadId);

	if (FsFilter->ThreadHandle == NULL) {
		NavFreeMem(FsFilter);
		return NAV_REGISTER_FS_FILTER_STATUS_FAILED;
	}

	*FilesystemFilter = FsFilter;

	return NAV_REGISTER_FS_FILTER_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavUnregisterFileSystemFilter(
	IN PNAV_FILESYSTEM_FILTER FilesystemFilter)
{
	if (TerminateThread(FilesystemFilter->ThreadHandle, EXIT_SUCCESS) == FALSE) {
		return NAV_UNREGISTER_FS_FILTER_STATUS_FAILED;
	}
	NavFreeMem(FilesystemFilter->Reserved);
	NavFreeMem(FilesystemFilter);
	return NAV_UNREGISTER_FS_FILTER_STATUS_SUCCESS;
}

HRESULT STDMETHODCALLTYPE NavProcessFilterCallback(
	IN CNavWmiEventSink* pCNavEvSink,
	IN LONG lObjectCount,
	IN IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray)
{
	for (LONG Idx = 0; Idx < lObjectCount; Idx++) {
		IWbemClassObject* pWbemObject = apObjArray[Idx];
		VARIANT Value = { 0 };
		CIMTYPE ValueType = 0;

		DWORD ProcessId = 0;
		DWORD ParentProcessId = 0;
		UINT64 CreationTime = 0;
		LPWSTR ProcessName = NULL;

		if (NavWmiCoReadPropertyByName(L"TIME_CREATED", &Value, pWbemObject, &ValueType) == FALSE)
			continue;
		CreationTime = V_UINT_PTR(&Value);

		if (NavWmiCoReadPropertyByName(L"ProcessId", &Value, pWbemObject, &ValueType) == FALSE)
			continue;
		ProcessId = V_UINT(&Value);

		if (NavWmiCoReadPropertyByName(L"ParentProcessId", &Value, pWbemObject, &ValueType) == FALSE)
			continue;
		ParentProcessId = V_UINT(&Value);

		if (pCNavEvSink->GetFlags() == NAV_PROCESS_NOTIFY_TYPE::TYPE_CREATION) {
			if (NavWmiCoReadPropertyByName(L"ProcessName", &Value, pWbemObject, &ValueType) == FALSE)
				continue;
			ProcessName = (LPWSTR)V_UINT_PTR(&Value);
		}
		
		PNAV_PROCESS_FILTER PsFilter = (PNAV_PROCESS_FILTER)pCNavEvSink->GetParameters();
		PNAV_PROCESS_DATA PsData = (PNAV_PROCESS_DATA)NavAllocMem(sizeof(NAV_PROCESS_DATA));

		PsData->ProcessId = ProcessId;
		PsData->ParentProcessId = ParentProcessId;
		PsData->CreationTime = CreationTime;
		PsData->ProcessName = ProcessName;

		PsFilter->FilterCallback(*PsData, (NAV_PROCESS_NOTIFY_TYPE)pCNavEvSink->GetFlags());

		NavFreeMem(PsData);
	}
	return WBEM_S_NO_ERROR;
}

NAVSTATUS NAVAPI NavRegisterProcessFilter(
	IN PNAV_PROCESS_FILTER_CALLBACK FilterCallback,
	OUT PNAV_PROCESS_FILTER* ProcessFilter)
{
	PNAV_PROCESS_FILTER PsFilter = (PNAV_PROCESS_FILTER)NavAllocMem(sizeof(NAV_PROCESS_FILTER));

	PsFilter->FilterCallback = FilterCallback;
	PsFilter->EventSinkCreation = new CNavWmiEventSink;
	PsFilter->EventSinkTermination = new CNavWmiEventSink;

	PsFilter->EventSinkCreation->RegisterCallback(NAV_WMI_CALLBACK_INDICATE, (PVOID)NavProcessFilterCallback);
	PsFilter->EventSinkCreation->SetParameters((PVOID)PsFilter);
	PsFilter->EventSinkCreation->SetFlags(NAV_PROCESS_NOTIFY_TYPE::TYPE_CREATION);

	PsFilter->EventSinkTermination->RegisterCallback(NAV_WMI_CALLBACK_INDICATE, (PVOID)NavProcessFilterCallback);
	PsFilter->EventSinkTermination->SetParameters((PVOID)PsFilter);
	PsFilter->EventSinkTermination->SetFlags(NAV_PROCESS_NOTIFY_TYPE::TYPE_TERMINATION);

	if (NavWmiCoInitializeEx() == FALSE){
		goto WMI_FAILURE;
	}
	if (NavWmiCoInitializeSecurity() == FALSE){
		goto WMI_FAILURE;
	}

	if (NavWmiCoCreateInstance(&PsFilter->LocatorCreation) == FALSE){
		goto WMI_FAILURE;
	}
	if (NavWmiCoCreateInstance(&PsFilter->LocatorTermination) == FALSE){
		goto WMI_FAILURE;
	}

	if (NavWmiCoConnectServer(PsFilter->LocatorCreation, &PsFilter->ServicesCreation) == FALSE){
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoConnectServer(PsFilter->LocatorTermination, &PsFilter->ServicesTermination) == FALSE){
		PsFilter->ServicesCreation->Release();
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		goto WMI_FAILURE;
	}

	if (NavWmiCoSetProxyBlanket(PsFilter->ServicesCreation) == FALSE){
		PsFilter->ServicesCreation->Release();
		PsFilter->ServicesTermination->Release();
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoSetProxyBlanket(PsFilter->ServicesTermination) == FALSE){
		PsFilter->ServicesCreation->Release();
		PsFilter->ServicesTermination->Release();
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		goto WMI_FAILURE;
	}

	if (NavWmiCoCreateUnsecuredApartment(&PsFilter->UnsecuredApartmentCreation,
		PsFilter->EventSinkCreation,
		&PsFilter->StubUnknownCreation,
		&PsFilter->ObjectSinkCreation) == FALSE)
	{
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		PsFilter->ServicesCreation->Release();
		PsFilter->ServicesTermination->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoCreateUnsecuredApartment(&PsFilter->UnsecuredApartmentTermination,
		PsFilter->EventSinkTermination,
		&PsFilter->StubUnknownTermination,
		&PsFilter->ObjectSinkTermination) == FALSE)
	{
		PsFilter->ServicesCreation->Release();
		PsFilter->ServicesTermination->Release();
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		PsFilter->UnsecuredApartmentCreation->Release();
		PsFilter->StubUnknownCreation->Release();
		PsFilter->ObjectSinkCreation->Release();
		goto WMI_FAILURE;
	}

	if (NavWmiCoExecNotificationQueryAsync(PsFilter->ServicesCreation, PsFilter->ObjectSinkCreation,
		L"WQL", L"SELECT * FROM Win32_ProcessStartTrace") == FALSE) 
	{
		PsFilter->ServicesCreation->Release();
		PsFilter->ServicesTermination->Release();
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		PsFilter->UnsecuredApartmentCreation->Release();
		PsFilter->UnsecuredApartmentTermination->Release();
		PsFilter->StubUnknownCreation->Release();
		PsFilter->StubUnknownTermination->Release();
		PsFilter->ObjectSinkCreation->Release();
		PsFilter->ObjectSinkTermination->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoExecNotificationQueryAsync(PsFilter->ServicesTermination, PsFilter->ObjectSinkTermination,
		L"WQL", L"SELECT * FROM Win32_ProcessStopTrace") == FALSE)
	{
		PsFilter->ServicesCreation->Release();
		PsFilter->ServicesTermination->Release();
		PsFilter->LocatorCreation->Release();
		PsFilter->LocatorTermination->Release();
		PsFilter->UnsecuredApartmentCreation->Release();
		PsFilter->UnsecuredApartmentTermination->Release();
		PsFilter->StubUnknownCreation->Release();
		PsFilter->StubUnknownTermination->Release();
		PsFilter->ObjectSinkCreation->Release();
		PsFilter->ObjectSinkTermination->Release();
		goto WMI_FAILURE;
	}

	*ProcessFilter = PsFilter;

	return NAV_REGISTER_PROCESS_FILTER_STATUS_SUCCESS;

WMI_FAILURE:
	delete PsFilter->EventSinkCreation;
	delete PsFilter->EventSinkTermination;
	NavWmiCoUninitialize();
	return NAV_REGISTER_PROCESS_FILTER_STATUS_FAILED;
}

NAVSTATUS NAVAPI NavUnregisterProcessFilter(
	IN PNAV_PROCESS_FILTER ProcessFilter)
{
	if (NavWmiCoCancelNotificationQueryAsync(
		ProcessFilter->ServicesCreation, ProcessFilter->ObjectSinkCreation) == FALSE)
		return NAV_UNREGISTER_PROCESS_FILTER_STATUS_FAILED;
	if (NavWmiCoCancelNotificationQueryAsync(
		ProcessFilter->ServicesTermination, ProcessFilter->ObjectSinkTermination) == FALSE)
		return NAV_UNREGISTER_PROCESS_FILTER_STATUS_FAILED;

	ProcessFilter->ServicesCreation->Release();
	ProcessFilter->ServicesTermination->Release();
	ProcessFilter->LocatorCreation->Release();
	ProcessFilter->LocatorTermination->Release();
	ProcessFilter->UnsecuredApartmentCreation->Release();
	ProcessFilter->UnsecuredApartmentTermination->Release();
	ProcessFilter->StubUnknownCreation->Release();
	ProcessFilter->StubUnknownTermination->Release();
	ProcessFilter->ObjectSinkCreation->Release();
	ProcessFilter->ObjectSinkTermination->Release();
	delete ProcessFilter->EventSinkCreation;
	delete ProcessFilter->EventSinkTermination;

	NavFreeMem(ProcessFilter);

	return NAV_UNREGISTER_PROCESS_FILTER_STATUS_SUCCESS;
}

HRESULT STDMETHODCALLTYPE NavPnpDeviceFilterCallback(
	IN CNavWmiEventSink* pCNavEvSink,
	IN LONG lObjectCount,
	IN IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray)
{
	for (LONG Idx = 0; Idx < lObjectCount; Idx++) {
		IWbemClassObject* pWbemObject = apObjArray[Idx];
		VARIANT Value = { 0 };
		CIMTYPE ValueType = 0;

		UINT64 CreationTime = 0;
		LPWSTR DriveName = NULL;

		if (NavWmiCoReadPropertyByName(L"TIME_CREATED", &Value, pWbemObject, &ValueType) == FALSE)
			continue;
		CreationTime = V_UINT_PTR(&Value);
		if (NavWmiCoReadPropertyByName(L"DriveName", &Value, pWbemObject, &ValueType) == FALSE)
			continue;
		DriveName = (LPWSTR)V_UINT_PTR(&Value);

		PNAV_PNP_DEVICE_FILTER PnpFilter = (PNAV_PNP_DEVICE_FILTER)pCNavEvSink->GetParameters();
		PNAV_PNP_DEVICE_DATA PnpData = (PNAV_PNP_DEVICE_DATA)NavAllocMem(sizeof(NAV_PNP_DEVICE_DATA));

		PnpData->CreationTime = CreationTime;
		PnpData->DriveName = DriveName;

		PnpFilter->FilterCallback(*PnpData, (NAV_PNP_DEVICE_NOTIFY_TYPE)pCNavEvSink->GetFlags());

		NavFreeMem(PnpData);
	}
	return WBEM_S_NO_ERROR;
}

NAVSTATUS NAVAPI NavRegisterPnpDeviceFilter(
	IN PNAV_PNP_DEVICE_FILTER_CALLBACK FilterCallback,
	OUT PNAV_PNP_DEVICE_FILTER* DeviceFilter)
{
	PNAV_PNP_DEVICE_FILTER PnpFilter = (PNAV_PNP_DEVICE_FILTER)NavAllocMem(sizeof(NAV_PNP_DEVICE_FILTER));

	PnpFilter->FilterCallback = FilterCallback;
	PnpFilter->EventSinkInserted = new CNavWmiEventSink;
	PnpFilter->EventSinkRemoved = new CNavWmiEventSink;

	PnpFilter->EventSinkInserted->RegisterCallback(NAV_WMI_CALLBACK_INDICATE, (PVOID)NavPnpDeviceFilterCallback);
	PnpFilter->EventSinkInserted->SetParameters((PVOID)PnpFilter);
	PnpFilter->EventSinkInserted->SetFlags(NAV_PNP_DEVICE_NOTIFY_TYPE::TYPE_INSERT);

	PnpFilter->EventSinkRemoved->RegisterCallback(NAV_WMI_CALLBACK_INDICATE, (PVOID)NavPnpDeviceFilterCallback);
	PnpFilter->EventSinkRemoved->SetParameters((PVOID)PnpFilter);
	PnpFilter->EventSinkRemoved->SetFlags(NAV_PNP_DEVICE_NOTIFY_TYPE::TYPE_REMOVE);

	if (NavWmiCoInitializeEx() == FALSE) {
		goto WMI_FAILURE;
	}
	if (NavWmiCoInitializeSecurity() == FALSE) {
		goto WMI_FAILURE;
	}

	if (NavWmiCoCreateInstance(&PnpFilter->LocatorInserted) == FALSE) {
		goto WMI_FAILURE;
	}
	if (NavWmiCoCreateInstance(&PnpFilter->LocatorRemoved) == FALSE) {
		goto WMI_FAILURE;
	}

	if (NavWmiCoConnectServer(PnpFilter->LocatorInserted, &PnpFilter->ServicesInserted) == FALSE) {
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoConnectServer(PnpFilter->LocatorRemoved, &PnpFilter->ServicesRemoved) == FALSE) {
		PnpFilter->ServicesInserted->Release();
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		goto WMI_FAILURE;
	}

	if (NavWmiCoSetProxyBlanket(PnpFilter->ServicesInserted) == FALSE) {
		PnpFilter->ServicesInserted->Release();
		PnpFilter->ServicesRemoved->Release();
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoSetProxyBlanket(PnpFilter->ServicesRemoved) == FALSE) {
		PnpFilter->ServicesInserted->Release();
		PnpFilter->ServicesRemoved->Release();
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		goto WMI_FAILURE;
	}

	if (NavWmiCoCreateUnsecuredApartment(&PnpFilter->UnsecuredApartmentInserted,
		PnpFilter->EventSinkInserted,
		&PnpFilter->StubUnknownInserted,
		&PnpFilter->ObjectSinkInserted) == FALSE)
	{
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		PnpFilter->ServicesInserted->Release();
		PnpFilter->ServicesRemoved->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoCreateUnsecuredApartment(&PnpFilter->UnsecuredApartmentRemoved,
		PnpFilter->EventSinkRemoved,
		&PnpFilter->StubUnknownRemoved,
		&PnpFilter->ObjectSinkRemoved) == FALSE)
	{
		PnpFilter->ServicesInserted->Release();
		PnpFilter->ServicesRemoved->Release();
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		PnpFilter->UnsecuredApartmentInserted->Release();
		PnpFilter->StubUnknownInserted->Release();
		PnpFilter->ObjectSinkInserted->Release();
		goto WMI_FAILURE;
	}

	if (NavWmiCoExecNotificationQueryAsync(PnpFilter->ServicesInserted, PnpFilter->ObjectSinkInserted,
		L"WQL", L"SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 2") == FALSE)
	{
		PnpFilter->ServicesInserted->Release();
		PnpFilter->ServicesRemoved->Release();
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		PnpFilter->UnsecuredApartmentInserted->Release();
		PnpFilter->UnsecuredApartmentRemoved->Release();
		PnpFilter->StubUnknownInserted->Release();
		PnpFilter->StubUnknownRemoved->Release();
		PnpFilter->ObjectSinkInserted->Release();
		PnpFilter->ObjectSinkRemoved->Release();
		goto WMI_FAILURE;
	}
	if (NavWmiCoExecNotificationQueryAsync(PnpFilter->ServicesRemoved, PnpFilter->ObjectSinkRemoved,
		L"WQL", L"SELECT * FROM Win32_DeviceChangeEvent WHERE EventType = 3") == FALSE)
	{
		PnpFilter->ServicesInserted->Release();
		PnpFilter->ServicesRemoved->Release();
		PnpFilter->LocatorInserted->Release();
		PnpFilter->LocatorRemoved->Release();
		PnpFilter->UnsecuredApartmentInserted->Release();
		PnpFilter->UnsecuredApartmentRemoved->Release();
		PnpFilter->StubUnknownInserted->Release();
		PnpFilter->StubUnknownRemoved->Release();
		PnpFilter->ObjectSinkInserted->Release();
		PnpFilter->ObjectSinkRemoved->Release();
		goto WMI_FAILURE;
	}

	*DeviceFilter = PnpFilter;

	return NAV_REGISTER_PNP_DEVICE_FILTER_STATUS_SUCCESS;

WMI_FAILURE:
	delete PnpFilter->EventSinkInserted;
	delete PnpFilter->EventSinkRemoved;
	NavWmiCoUninitialize();
	return NAV_REGISTER_PNP_DEVICE_FILTER_STATUS_FAILED;
}

NAVSTATUS NAVAPI NavUnregisterPnpDeviceFilter(
	PNAV_PNP_DEVICE_FILTER PnpFilter)
{
	if (NavWmiCoCancelNotificationQueryAsync(
		PnpFilter->ServicesInserted, PnpFilter->ObjectSinkInserted) == FALSE)
		return NAV_UNREGISTER_PNP_DEVICE_FILTER_STATUS_FAILED;
	if (NavWmiCoCancelNotificationQueryAsync(
		PnpFilter->ServicesRemoved, PnpFilter->ObjectSinkRemoved) == FALSE)
		return NAV_UNREGISTER_PNP_DEVICE_FILTER_STATUS_FAILED;

	PnpFilter->ServicesInserted->Release();
	PnpFilter->ServicesRemoved->Release();
	PnpFilter->LocatorInserted->Release();
	PnpFilter->LocatorRemoved->Release();
	PnpFilter->UnsecuredApartmentInserted->Release();
	PnpFilter->UnsecuredApartmentRemoved->Release();
	PnpFilter->StubUnknownInserted->Release();
	PnpFilter->StubUnknownRemoved->Release();
	PnpFilter->ObjectSinkInserted->Release();
	PnpFilter->ObjectSinkRemoved->Release();
	delete PnpFilter->EventSinkInserted;
	delete PnpFilter->EventSinkRemoved;

	NavFreeMem(PnpFilter);

	return NAV_UNREGISTER_PNP_DEVICE_FILTER_STATUS_SUCCESS;
}