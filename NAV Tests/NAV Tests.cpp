// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#include <iostream>
#include "nav/status.h"
#include "nav/protection.h"


int main()
{
	DWORD SidSize = 0;
	PSID Everyone = NULL;

	NavCreateWellKnownSid(WELL_KNOWN_SID_TYPE::WinWorldSid, NULL, &Everyone, &SidSize);

	NAVSTATUS status = NavSetProcessKernelAce(
		GetCurrentProcess(), 
		ACCESS_MODE::DENY_ACCESS, 
		PROCESS_VM_WRITE | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION,
		TRUSTEE_FORM::TRUSTEE_IS_SID, 
		TRUSTEE_TYPE::TRUSTEE_IS_WELL_KNOWN_GROUP,
		(LPVOID)Everyone);

	NavFreeWellKnownSid(&Everyone);

	DWORD error = GetLastError();

	getchar();
	return ERROR_SUCCESS;
}

