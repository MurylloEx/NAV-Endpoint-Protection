#pragma once

#include "winapi.h"
#include "status.h"
#include "memory.h"
#include <accctrl.h>
#include <AclAPI.h>

typedef DWORD ACCESS_PERMISSIONS, *PACCESS_PERMISSIONS;

NAVSTATUS NavCreateWellKnownSid(
	IN WELL_KNOWN_SID_TYPE SidType,
	IN PSID DomainSid,
	IN PSID* SidPtr,
	OUT DWORD* SidSizePtr);

NAVSTATUS NavFreeWellKnownSid(
	IN PSID* SidPtr);

NAVSTATUS NavSetProcessKernelAce(
	IN HANDLE ProcessHandle,
	IN ACCESS_MODE AccessMode,
	IN ACCESS_PERMISSIONS DesiredAccess,
	IN TRUSTEE_FORM TrusteeFormat,
	IN TRUSTEE_TYPE TrusteeType,
	IN LPVOID TrusteeName);