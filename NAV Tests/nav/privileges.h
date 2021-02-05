#pragma once

#include "winapi.h"
#include "status.h"
#include "memory.h"

NAVSTATUS NAVAPI NavEnableTokenPrivileges(
	IN HANDLE TokenHandle,
	IN LPWSTR PrivilegeName,
	IN BOOL EnablePrivilege);

NAVSTATUS NAVAPI NavOpenProcessToken(
	IN DWORD ProcessId,
	OUT PHANDLE TokenHandle,
	IN DWORD TokenOptionalAccess);

NAVSTATUS NAVAPI NavCloseProcessToken(
	IN HANDLE TokenHandle);

NAVSTATUS NAVAPI NavCheckPrivilegeToken(
	IN HANDLE TokenHandle,
	IN LPWSTR PrivilegeName,
	OUT PBOOL BooleanResult);