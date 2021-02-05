#pragma once

#include "winapi.h"
#include "status.h"
#include "memory.h"
#include <accctrl.h>
#include <AclAPI.h>

typedef DWORD ACCESS_PERMISSIONS, *PACCESS_PERMISSIONS;

typedef struct _NAV_SECURITY_DESCRIPTOR {
	PSECURITY_DESCRIPTOR AbSecurityDescriptor;
	DWORD AbSecurityDescriptorSize;
	PACL DiscretionaryACL;
	PACL SystemACL;
	DWORD DiscretionaryACLSize;
	DWORD SystemACLSize;
	PSID OwnerSID;
	PSID PrimaryGroupSID;
	DWORD OwnerSIDSize;
	DWORD PrimaryGroupSIDSize;
} NAV_SECURITY_DESCRIPTOR, *LPNAV_SECURITY_DESCRIPTOR;

NAVSTATUS NAVAPI NavCreateWellKnownSid(
	IN WELL_KNOWN_SID_TYPE SidType,
	IN PSID DomainSid,
	IN PSID* SidPtr,
	OUT DWORD* SidSizePtr);

NAVSTATUS NAVAPI NavFreeWellKnownSid(
	IN PSID* SidPtr);

NAVSTATUS NAVAPI NavKeMakeAbDescriptor(
	IN PSECURITY_DESCRIPTOR* RelativeSecurityDescriptor,
	OUT LPNAV_SECURITY_DESCRIPTOR* NavSecurityDescriptor);

NAVSTATUS NAVAPI NavKeFreeAbDescriptor(
	IN LPNAV_SECURITY_DESCRIPTOR* NavSecurityDescriptor);

NAVSTATUS NAVAPI NavKeSetProcessAce(
	IN HANDLE ProcessHandle,
	IN ACCESS_MODE AccessMode,
	IN ACCESS_PERMISSIONS AccessPermissions,
	IN TRUSTEE_FORM TrusteeFormat,
	IN TRUSTEE_TYPE TrusteeType,
	IN LPVOID TrusteeName);

NAVSTATUS NAVAPI NavKeProtectProcess(
	IN HANDLE ProcessHandle,
	IN BOOL ProtectionState);

NAVSTATUS NAVAPI NavKeSetFileAce(
	IN LPCWSTR FileName,
	IN ACCESS_MODE AccessMode,
	IN ACCESS_PERMISSIONS AccessPermissions,
	IN TRUSTEE_FORM TrusteeFormat,
	IN TRUSTEE_TYPE TrusteeType,
	IN LPVOID TrusteeName);

NAVSTATUS NAVAPI NavKeSetKeyAce(
	IN HKEY KeyHandle,
	IN ACCESS_MODE AccessMode,
	IN ACCESS_PERMISSIONS AccessPermissions,
	IN TRUSTEE_FORM TrusteeFormat,
	IN TRUSTEE_TYPE TrusteeType,
	IN LPVOID TrusteeName);

