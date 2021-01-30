#pragma once

#include "winapi.h"
#include "status.h"
#include "memory.h"

NAVSTATUS NavEnableTokenPrivileges(
	IN HANDLE TokenHandle,
	IN LPWSTR PrivilegeName,
	IN BOOL EnablePrivilege);

NAVSTATUS NavOpenProcessToken(
	IN DWORD ProcessId,
	OUT PHANDLE TokenHandle,
	IN DWORD TokenOptionalAccess);

NAVSTATUS NavCloseProcessToken(
	IN HANDLE TokenHandle);

NAVSTATUS NavCheckPrivilegeToken(
	IN HANDLE TokenHandle,
	IN LPWSTR PrivilegeName,
	OUT PBOOL BooleanResult);