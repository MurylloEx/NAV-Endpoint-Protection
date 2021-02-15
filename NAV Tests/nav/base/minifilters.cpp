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