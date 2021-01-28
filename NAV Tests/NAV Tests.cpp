// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>

#include "nav/handles.h"

int main()
{
	
	BOOL valor = 0;

	//while (true) {
		//valor++;

		PNAV_PROCESS_HANDLES ptrNavHandles = (PNAV_PROCESS_HANDLES)NavAllocMem(sizeof(NAV_PROCESS_HANDLES));
		NavGetProcessHandles(10548, ptrNavHandles);

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

	
		
	getchar();
	return ERROR_SUCCESS;
}

