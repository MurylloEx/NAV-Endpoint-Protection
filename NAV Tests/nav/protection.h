#pragma once

#include "winapi.h"
#include "status.h"
#include "memory.h"
#include <accctrl.h>
#include <AclAPI.h>

NAVSTATUS NavSetProcessKernelAce(
	IN HANDLE ProcessHandle,
	IN ACCESS_MODE AccessMode,
	IN TRUSTEE_FORM TrusteeFormat,
	IN LPWSTR TrusteeName);