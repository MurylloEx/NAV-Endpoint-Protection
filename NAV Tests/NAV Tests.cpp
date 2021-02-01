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

	LPCWSTR FileName = L"C:\\Users\\Murilo\\Desktop\\teste.exe";
	
	NAVSTATUS Status = NavKeSetFileAce(FileName,
		ACCESS_MODE::DENY_ACCESS,
		GENERIC_READ,
		TRUSTEE_FORM::TRUSTEE_IS_SID,
		TRUSTEE_TYPE::TRUSTEE_IS_WELL_KNOWN_GROUP,
		(LPVOID)Everyone);

	NavFreeWellKnownSid(&Everyone);

	getchar();
	return ERROR_SUCCESS;
}

