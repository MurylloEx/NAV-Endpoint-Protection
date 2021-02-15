// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

//#include <vld.h>
#include <stdio.h>
#include "nav/base/minifilters.h"


VOID NAVAPI FsCallback(
	NAV_FILESYSTEM_FILE_DATA FileData, 
	NAV_FILESYSTEM_ACTION_TYPE Action, 
	NAV_FILESYSTEM_FILE_TYPE Type) 
{
	if (Action == NAV_FILESYSTEM_ACTION_TYPE::ACTION_CREATED) {
		wprintf(L"%s --> %d\n", FileData.SrcFileName, Type);
	}
}

int main(VOID)
{
	PNAV_FILESYSTEM_FILTER fsflt = NULL;
	NavRegisterFileSystemFilter(L"\\\\?\\C:\\", GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_BACKUP_SEMANTICS, 65536,
		FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_CREATION | 
		FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME, TRUE, FsCallback, &fsflt);
	getchar();
}
