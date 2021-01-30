// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>
#include "nav/status.h"
#include "nav/privileges.h"


int main()
{
	DWORD ProcessId = GetCurrentProcessId();
	HANDLE TokenHandle = NULL;
	BOOL Result = FALSE;

	if (NAV_SUCCESS(NavOpenProcessToken(ProcessId, &TokenHandle))) {
		printf("Token aberto");
	}

	NAVSTATUS status1 = NavEnableTokenPrivileges(TokenHandle, (LPWSTR)SE_DEBUG_NAME, TRUE);

	ULONG valor = GetLastError();


	NAVSTATUS status = NavCheckPrivilegeToken(TokenHandle, (LPWSTR)SE_DEBUG_NAME, &Result);

	


	getchar();
	return ERROR_SUCCESS;
}

