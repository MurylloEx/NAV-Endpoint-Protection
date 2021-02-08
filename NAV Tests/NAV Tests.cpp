// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

//#include <vld.h>
#include <stdio.h>
#include "nav/base/memory.h"
#include "nav/base/winapi.h"




typedef enum _NAV_FILESYSTEM_FILE_TYPE {
	TYPE_FILE,
	TYPE_DIRECTORY
} NAV_FILESYSTEM_FILE_TYPE, *PNAV_FILESYSTEM_FILE_TYPE;

typedef VOID(NAVAPI* PNAV_FILESYSTEM_FILTER_CALLBACK)(
	IN LPWSTR FileName,
	IN DWORD Action,
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
	PNAV_FILESYSTEM_FILTER_CALLBACK FilterCallback;
} NAV_FILESYSTEM_FILTER, *PNAV_FILESYSTEM_FILTER;

DWORD WINAPI NavFileSystemFilterThread(LPVOID Params) {
	PNAV_FILESYSTEM_FILTER FsFilter = (PNAV_FILESYSTEM_FILTER)Params;
	HANDLE FileHandle = CreateFileW(FsFilter->FileName, FsFilter->FileAccess, FsFilter->FileShare, 
		NULL, OPEN_EXISTING, FsFilter->FlagsAndAttributes, NULL);

	if (FileHandle == INVALID_HANDLE_VALUE) {
		return EXIT_FAILURE;
	}

	LPVOID Buffer = NavAllocMem(FsFilter->BufferSize);
	
	if (Buffer == NULL) {
		return EXIT_FAILURE;
	}

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

		if (Status == FALSE)
			continue;

		Status = GetOverlappedResult(FileHandle, &Overlapped, &BytesTransferred, FALSE);

		do {
			FileNotify = (FILE_NOTIFY_INFORMATION*)((ULONG_PTR)Buffer + NotifyOffset);

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
		return EXIT_FAILURE;
	}

	FsFilter->FileName = FileName;
	FsFilter->FileAccess = FileAccess;
	FsFilter->FileShare = FileShare;
	FsFilter->FlagsAndAttributes = FlagsAndAttributes;
	FsFilter->BufferSize = BufferSize;
	FsFilter->NotifyChanges = NotifyChanges;
	FsFilter->WatchSubtrees = WatchSubtrees;
	FsFilter->FilterCallback = FilterCallback;

	FsFilter->ThreadHandle = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)NavFileSystemFilterThread,
		FsFilter, NULL, &FsFilter->ThreadId);

	if (FsFilter->ThreadHandle == NULL) {
		NavFreeMem(FsFilter);
		return EXIT_FAILURE;
	}

	*FilesystemFilter = FsFilter;

	return EXIT_SUCCESS;
}


int main(VOID)
{
	PNAV_FILESYSTEM_FILTER fsflt = NULL;
	NavRegisterFileSystemFilter(L"C:\\Users", GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_BACKUP_SEMANTICS, 65536,
		FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
		FILE_NOTIFY_CHANGE_CREATION, TRUE, NULL, &fsflt);
	getchar();
}
