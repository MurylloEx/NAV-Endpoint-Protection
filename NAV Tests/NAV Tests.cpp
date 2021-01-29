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

	PNAV_PROCESS_HANDLES handles = (PNAV_PROCESS_HANDLES)NavAllocMem(sizeof(NAV_PROCESS_HANDLES));
	NavGetProcessHandles(6796, handles);

	PNAV_PROCESS_OPEN_FILES files = (PNAV_PROCESS_OPEN_FILES)NavAllocMem(sizeof(NAV_PROCESS_OPEN_FILES));
	NavGetFilesByProcessHandles(handles, files);

	PNAV_PROCESS_OPEN_KEYS keys = (PNAV_PROCESS_OPEN_KEYS)NavAllocMem(sizeof(NAV_PROCESS_OPEN_KEYS));
	NavGetKeysByProcessHandles(handles, keys);

	PNAV_PROCESS_OPEN_PROCESSES processes = (PNAV_PROCESS_OPEN_PROCESSES)NavAllocMem(sizeof(NAV_PROCESS_OPEN_PROCESSES));
	NavGetProcessesByProcessHandles(handles, processes);

	//wprintf(L"%s\n", ptrNavHandles->PObjectTypeInformation->Name.Buffer);

	//while (ptrNavHandles->NextAddress != NULL) {
		//ptrNavHandles = (PNAV_PROCESS_HANDLES)ptrNavHandles->NextAddress;
		//wprintf(L"%s\n", ptrNavHandles->PObjectTypeInformation->Name.Buffer);
	//}

	NavFreeOpenProcesses(processes);
	NavFreeOpenKeys(keys);
	NavFreeOpenFiles(files);
	NavFreeProcessHandles(handles);

	//}
}

int main()
{
	for (int i = 0; i < 10; i++) {
		tests();
	}
	
	//HANDLE hProcess = OpenProcess(
	//	PROCESS_ALL_ACCESS, FALSE, 6796);
	
	//wprintf_s(L"%s\n", NavQueryProcessPathNameById(hProcess));

	getchar();
	return ERROR_SUCCESS;
}

