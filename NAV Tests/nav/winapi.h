#pragma once

#include <Windows.h>

#define NTDLL							(LPSTR)"NTDLL.DLL"
#define NtQuerySystemInformationName	(LPSTR)"NtQuerySystemInformation"
#define NtDuplicateObjectName			(LPSTR)"NtDuplicateObject"
#define NtQueryObjectName				(LPSTR)"NtQueryObject"

FARPROC NavGetProcAddress(_In_ LPSTR LibraryName, _In_ LPSTR FunctionName);

