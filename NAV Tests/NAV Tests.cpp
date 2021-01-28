// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>
#include "nav/handles.h"

void tests() {
	BOOL valor = 0;

	//while (true) {
		//valor++;

	PNAV_PROCESS_HANDLES ptrNavHandles = (PNAV_PROCESS_HANDLES)NavAllocMem(sizeof(NAV_PROCESS_HANDLES));
	NavGetProcessHandles(17268, ptrNavHandles);

	PNAV_PROCESS_OPEN_FILES files = (PNAV_PROCESS_OPEN_FILES)NavAllocMem(sizeof(NAV_PROCESS_OPEN_FILES));
	NavGetFilesByProcessHandles(ptrNavHandles, files);

	std::wcout << files->FilePathName << std::endl;

	while (files->NextAddress != NULL) {
		files = (PNAV_PROCESS_OPEN_FILES)files->NextAddress;
		std::wcout << files->FilePathName << std::endl;
	}

	NavFreeOpenFiles(files);
	NavFreeProcessHandles(ptrNavHandles);

	//}
}

int main()
{
	PNAV_PROCESS_HANDLES ProcessHandles = (PNAV_PROCESS_HANDLES)NavAllocMem(sizeof(NAV_PROCESS_HANDLES));

	NavGetProcessHandles(10548, ProcessHandles);

	PNAV_PROCESS_OPEN_KEYS OpenKeys = (PNAV_PROCESS_OPEN_KEYS)NavAllocMem(sizeof(NAV_PROCESS_OPEN_KEYS));

	NavGetKeysByProcessHandles(ProcessHandles, OpenKeys);

	if (OpenKeys == NULL) {
		printf("Failed to allocate new memory block.\n");
		return EXIT_FAILURE;
	}

	wprintf(L"%s\n", OpenKeys->KeyPathName);

	while (OpenKeys->NextAddress != NULL) {
		OpenKeys = (PNAV_PROCESS_OPEN_KEYS)OpenKeys->NextAddress;
		wprintf(L"%s\n", OpenKeys->KeyPathName);
	}
	
	getchar();
	return ERROR_SUCCESS;
}

