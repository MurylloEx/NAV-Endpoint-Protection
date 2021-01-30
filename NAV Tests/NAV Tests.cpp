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

	if (NAV_SUCCESS(NavOpenProcessToken(ProcessId, &TokenHandle, NULL))) {
		printf("Opened token\n");
	}

	if (NAV_SUCCESS(NavEnableTokenPrivileges(TokenHandle, (LPWSTR)SE_DEBUG_NAME, TRUE))) {
		printf("Successfully enabled SE_DEBUG_NAME privilege\n");
	}

	if (NAV_SUCCESS(NavCheckPrivilegeToken(TokenHandle, (LPWSTR)SE_DEBUG_NAME, &Result))) {
		printf("Successfully checked SE_DEBUG_NAME privilege\n");
	}

	return ERROR_SUCCESS;
}

