#include <Windows.h>
#include <WtsApi32.h>
#include "status.h"

#pragma comment(lib, "Wtsapi32.lib")

NAVSTATUS NavCreateProcessAsImpersonatedUser(
	IN LPCWSTR ExecutablePath,
	IN LPCWSTR ExecutableDirectory,
	IN LPSECURITY_ATTRIBUTES ProcessSecurity,
	IN LPSECURITY_ATTRIBUTES ThreadSecurity,
	IN LPPROCESS_INFORMATION ProcessInformation,
	IN LPSTARTUPINFOW StartupInfo,
	IN DWORD CreationFlags);