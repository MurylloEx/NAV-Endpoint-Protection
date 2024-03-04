#include "privileges.h"

NAVSTATUS NAVAPI NavEnableTokenPrivileges(
	IN HANDLE TokenHandle,
	IN LPWSTR PrivilegeName,
	IN BOOL EnablePrivilege)
{
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	LUID Luid = { 0 };
	
	if (LookupPrivilegeValueW(NULL, PrivilegeName, &Luid) == FALSE) {
		return NAV_PRIVILEGE_STATUS_FAILED;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid = Luid;
	TokenPrivileges.Privileges[0].Attributes = 0;

	if (EnablePrivilege != FALSE) {
		TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	}

	if (AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL) == FALSE) {
		return NAV_PRIVILEGE_STATUS_ENABLE_FAILED;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		SetLastError(NULL);
		return NAV_PRIVILEGE_STATUS_NOT_ASSIGNED;
	}

	return NAV_PRIVILEGE_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavOpenProcessToken(
	IN DWORD ProcessId,
	OUT PHANDLE TokenHandle,
	IN DWORD TokenOptionalAccess)
{
	DWORD CurrentId = ProcessId;
	DWORD TokenAccess = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_READ | 
						TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT;
	*TokenHandle = NULL;

	if (TokenOptionalAccess != NULL)
		TokenAccess = TokenOptionalAccess;

	if (ProcessId == NULL)
		CurrentId = GetCurrentProcessId();

	HANDLE ProcessHandle = OpenProcess(STANDARD_RIGHTS_ALL | PROCESS_QUERY_INFORMATION, FALSE, CurrentId);
	
	if (ProcessHandle == NULL) {
		return NAV_TOKEN_STATUS_OPEN_PROCESS_FAILED;
	}

	if (OpenProcessToken(ProcessHandle, TokenAccess, TokenHandle) == FALSE) {
		return NAV_TOKEN_STATUS_FAILED;
	}

	return NAV_TOKEN_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavCloseProcessToken(
	IN HANDLE TokenHandle) 
{
	if (CloseHandle(TokenHandle) == TRUE) {
		return NAV_CLOSE_TOKEN_STATUS_SUCCESS;
	}
	return NAV_CLOSE_TOKEN_STATUS_FAILED;
}

NAVSTATUS NAVAPI NavCheckPrivilegeToken(
	IN HANDLE TokenHandle,
	IN LPWSTR PrivilegeName,
	OUT PBOOL BooleanResult)
{
	LUID Luid = { 0 };
	BOOL FlagResult = FALSE;
	DWORD TokenBufferSize = 0;
	BOOL Status = LookupPrivilegeValueW(NULL, PrivilegeName, &Luid);

	if (Status == FALSE) {
		/* Cannot query the privilege LUID value*/
		return NAV_CHECK_PRIVILEGE_STATUS_UNKNOWN_LUID;
	}

	*BooleanResult = FALSE;

	GetTokenInformation(TokenHandle, TOKEN_INFORMATION_CLASS::TokenPrivileges, 
		NULL, NULL, &TokenBufferSize);

	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		/* Cannot get the Token buffer size */
		return NAV_CHECK_PRIVILEGE_STATUS_UNKNOWN_BUFFER_SIZE;
	}
	
	PTOKEN_PRIVILEGES PTokenPrivileges = (PTOKEN_PRIVILEGES)NavAllocate(TokenBufferSize);

	Status = GetTokenInformation(TokenHandle, TOKEN_INFORMATION_CLASS::TokenPrivileges,
		PTokenPrivileges, TokenBufferSize, &TokenBufferSize);

	if (Status == FALSE) {
		/* Cannot get the Token information */
		return NAV_CHECK_PRIVILEGE_STATUS_UNKNOWN_INFO;
	}

	for (UINT Idx = 0; Idx < PTokenPrivileges->PrivilegeCount; Idx++) {
		LUID_AND_ATTRIBUTES &LuidAttributes = PTokenPrivileges->Privileges[Idx];
		if ((LuidAttributes.Luid.HighPart != Luid.HighPart) || (LuidAttributes.Luid.LowPart != Luid.LowPart)) {
			continue;
		}
		if ((LuidAttributes.Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED) {
			*BooleanResult = TRUE;
		}
	}

	NavFree(PTokenPrivileges);
	
	return NAV_CHECK_PRIVILEGE_STATUS_SUCCESS;
}