#include "service.h"

NAVSTATUS NAVAPI NavCreateProcessAsImpersonatedUser(
	IN LPCWSTR ExecutablePath,
	IN LPCWSTR ExecutableDirectory,
	IN LPSECURITY_ATTRIBUTES ProcessSecurity,
	IN LPSECURITY_ATTRIBUTES ThreadSecurity,
	IN LPPROCESS_INFORMATION ProcessInformation,
	IN LPSTARTUPINFOW StartupInfo,
	IN DWORD CreationFlags)
{	
	HANDLE* UserToken = NULL;
	DWORD SessionId = WTSGetActiveConsoleSessionId();
	if (SessionId == 0xffffffff) {
		return NAV_CREATE_PROCESS_STATUS_INVALID_SESSION;
	}

	BOOL QueryStatus = WTSQueryUserToken(SessionId, UserToken);
	if (QueryStatus == FALSE) {
		return NAV_CREATE_PROCESS_STATUS_INVALID_USER_TOKEN;
	}

	BOOL ProcessStatus = CreateProcessAsUserW(*UserToken, ExecutablePath, NULL, ProcessSecurity, 
		ThreadSecurity, FALSE, CreationFlags, NULL, ExecutableDirectory, 
		StartupInfo, ProcessInformation);

	CloseHandle(*UserToken);

	if (ProcessStatus == FALSE) {
		return NAV_CREATE_PROCESS_STATUS_FAILED;
	}
	return NAV_CREATE_PROCESS_STATUS_SUCCESS;
}