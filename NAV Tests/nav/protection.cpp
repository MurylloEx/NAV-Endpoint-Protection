#include "protection.h"
#include "privileges.h"

NAVSTATUS NAVAPI NavCreateWellKnownSid(
	IN WELL_KNOWN_SID_TYPE SidType,
	IN PSID DomainSid,
	IN PSID* SidPtr,
	OUT DWORD* SidSizePtr) 
{
	DWORD SidSize = sizeof(SID);
	PSID PSid = (PSID)NavAllocMem(SidSize);
	if (PSid == NULL) {
		return NAV_CREATE_SID_STATUS_MEMORY_ALLOCATION_FAILED;
	}
	BOOL Status = CreateWellKnownSid(SidType, DomainSid, PSid, &SidSize);
	if (Status != FALSE) {
		*SidPtr = PSid;
		*SidSizePtr = SidSize;
		return NAV_CREATE_SID_STATUS_SUCCESS;
	}
	if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
		if (CreateWellKnownSid(SidType, DomainSid, PSid, &SidSize) == FALSE) {
			NavFreeMem(PSid);
			return NAV_CREATE_SID_STATUS_CREATION_FAILED;
		}
	}
	*SidPtr = PSid;
	*SidSizePtr = SidSize;
	return NAV_CREATE_SID_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavFreeWellKnownSid(
	IN PSID* SidPtr)
{
	if (NavFreeMem((LPVOID)(*SidPtr)) == FALSE) {
		return NAV_FREE_SID_STATUS_FAILED;
	}
	return NAV_FREE_SID_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavKeMakeAbDescriptor(
	IN PSECURITY_DESCRIPTOR* RelativeSecurityDescriptor,
	OUT LPNAV_SECURITY_DESCRIPTOR* NavSecurityDescriptor)
{
	*NavSecurityDescriptor = (LPNAV_SECURITY_DESCRIPTOR)NavAllocMem(sizeof(NAV_SECURITY_DESCRIPTOR));

	if (*NavSecurityDescriptor == NULL) {
		return NAV_MAKE_SD_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	LPVOID AbSDSize				= &((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->AbSecurityDescriptorSize;
	LPVOID DaclSize				= &((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->DiscretionaryACLSize;
	LPVOID SaclSize				= &((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->SystemACLSize;
	LPVOID OwnerSIDSize			= &((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->OwnerSIDSize;
	LPVOID PrimaryGroupSIDSize	= &((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->PrimaryGroupSIDSize;

	*(PDWORD)AbSDSize				= sizeof(SECURITY_DESCRIPTOR);
	*(PDWORD)DaclSize				= sizeof(ACL);
	*(PDWORD)SaclSize				= sizeof(ACL);
	*(PDWORD)OwnerSIDSize			= sizeof(SID);
	*(PDWORD)PrimaryGroupSIDSize	= sizeof(SID);

	PVOID AbSecurityDescriptor	= (PVOID)NavAllocMem(*(PDWORD)AbSDSize);
	PACL Dacl					= (PACL)NavAllocMem(*(PDWORD)DaclSize);
	PACL Sacl					= (PACL)NavAllocMem(*(PDWORD)SaclSize);
	PSID OwnerSID				= (PSID)NavAllocMem(*(PDWORD)OwnerSIDSize);
	PSID PrimaryGroupSID		= (PSID)NavAllocMem(*(PDWORD)PrimaryGroupSIDSize);

	if (!AbSecurityDescriptor || !Dacl || !Sacl || !OwnerSID || !PrimaryGroupSID) {
		/* Free all allocated memory blocks */
		NavFreeMem(*NavSecurityDescriptor);
		NavFreeMem(AbSecurityDescriptor);
		NavFreeMem(Dacl);
		NavFreeMem(Sacl);
		NavFreeMem(OwnerSID);
		NavFreeMem(PrimaryGroupSID);
		return NAV_MAKE_SD_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	BOOL ConversionStatus = MakeAbsoluteSD(*RelativeSecurityDescriptor, (PSECURITY_DESCRIPTOR)AbSecurityDescriptor,
		(PDWORD)AbSDSize, Dacl, (PDWORD)DaclSize, Sacl, (PDWORD)SaclSize, OwnerSID, 
		(PDWORD)OwnerSIDSize, PrimaryGroupSID, (PDWORD)PrimaryGroupSIDSize);

	if ((ConversionStatus == FALSE) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {

		AbSecurityDescriptor	= (PSECURITY_DESCRIPTOR)NavReAllocMem(AbSecurityDescriptor, *(PDWORD)AbSDSize);
		Dacl					= (PACL)NavReAllocMem(Dacl, *(PDWORD)DaclSize);
		Sacl					= (PACL)NavReAllocMem(Sacl, *(PDWORD)SaclSize);
		OwnerSID				= (PSID)NavReAllocMem(OwnerSID, *(PDWORD)OwnerSIDSize);
		PrimaryGroupSID			= (PSID)NavReAllocMem(PrimaryGroupSID, *(PDWORD)PrimaryGroupSIDSize);

		if (!AbSecurityDescriptor || !Dacl || !Sacl || !OwnerSID || !PrimaryGroupSID) {
			/* Free all allocated memory blocks */
			NavFreeMem(*NavSecurityDescriptor);
			NavFreeMem(AbSecurityDescriptor);
			NavFreeMem(Dacl);
			NavFreeMem(Sacl);
			NavFreeMem(OwnerSID);
			NavFreeMem(PrimaryGroupSID);
			return NAV_MAKE_SD_STATUS_MEMORY_ALLOCATION_FAILED;
		}

		ConversionStatus = MakeAbsoluteSD(*RelativeSecurityDescriptor, (PSECURITY_DESCRIPTOR)AbSecurityDescriptor,
			(PDWORD)AbSDSize, Dacl, (PDWORD)DaclSize, Sacl, (PDWORD)SaclSize, OwnerSID,
			(PDWORD)OwnerSIDSize, PrimaryGroupSID, (PDWORD)PrimaryGroupSIDSize);

		if (ConversionStatus == FALSE) {
			/* Free all allocated memory blocks */
			NavFreeMem(*NavSecurityDescriptor);
			NavFreeMem(AbSecurityDescriptor);
			NavFreeMem(Dacl);
			NavFreeMem(Sacl);
			NavFreeMem(OwnerSID);
			NavFreeMem(PrimaryGroupSID);
			return NAV_MAKE_SD_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
		}
	}

	((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->AbSecurityDescriptor = (PSECURITY_DESCRIPTOR)AbSecurityDescriptor;
	((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->DiscretionaryACL = Dacl;
	((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->SystemACL = Sacl;
	((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->OwnerSID = OwnerSID;
	((LPNAV_SECURITY_DESCRIPTOR)(*NavSecurityDescriptor))->PrimaryGroupSID = PrimaryGroupSID;

	return NAV_MAKE_SD_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavKeFreeAbDescriptor(
	IN LPNAV_SECURITY_DESCRIPTOR* NavSecurityDescriptor)
{
	LPNAV_SECURITY_DESCRIPTOR RefNavSecurityDescriptor = *NavSecurityDescriptor;

	/* Release all memory used by NAV Security Descriptor */
	NavFreeMem(RefNavSecurityDescriptor->AbSecurityDescriptor);
	NavFreeMem(RefNavSecurityDescriptor->DiscretionaryACL);
	NavFreeMem(RefNavSecurityDescriptor->SystemACL);
	NavFreeMem(RefNavSecurityDescriptor->OwnerSID);
	NavFreeMem(RefNavSecurityDescriptor->PrimaryGroupSID);
	NavFreeMem(RefNavSecurityDescriptor);

	return NAV_FREE_SD_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavKeSetProcessAce(
	IN HANDLE ProcessHandle,
	IN ACCESS_MODE AccessMode,
	IN ACCESS_PERMISSIONS AccessPermissions,
	IN TRUSTEE_FORM TrusteeFormat,
	IN TRUSTEE_TYPE TrusteeType,
	IN LPVOID TrusteeName)
{
	DWORD BufferSize = 0;
	
	GetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, NULL, BufferSize, &BufferSize);
	
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return NAV_PROCESS_ACE_STATUS_UNKNOWN_BUFFER_SIZE;
	}

	PSECURITY_DESCRIPTOR RelSecurityDescriptor = (PSECURITY_DESCRIPTOR)NavAllocMem(BufferSize);

	if (RelSecurityDescriptor == FALSE) {
		return NAV_PROCESS_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	if (GetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, RelSecurityDescriptor, BufferSize, &BufferSize) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_PROCESS_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	LPNAV_SECURITY_DESCRIPTOR NavSecurityDescriptor = NULL;

	NAVSTATUS AbDescriptorStatus = NavKeMakeAbDescriptor(&RelSecurityDescriptor, &NavSecurityDescriptor);

	if (!NAV_SUCCESS(AbDescriptorStatus)) {
		if (AbDescriptorStatus == NAV_MAKE_SD_STATUS_MEMORY_ALLOCATION_FAILED)
			return NAV_PROCESS_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
		if (AbDescriptorStatus == NAV_MAKE_SD_STATUS_UNKNOWN_SECURITY_DESCRIPTOR)
			return NAV_PROCESS_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	PACL NewAcl = NULL;
	PACL OldAcl = NULL;
	EXPLICIT_ACCESS_W ExplicitAccess = { 0 };
	ZeroMemory(&ExplicitAccess, sizeof(EXPLICIT_ACCESS_W));

	ExplicitAccess.grfAccessMode = AccessMode;
	ExplicitAccess.grfAccessPermissions = AccessPermissions;
	ExplicitAccess.grfInheritance = NO_INHERITANCE;
	ExplicitAccess.Trustee.TrusteeForm = TrusteeFormat;
	ExplicitAccess.Trustee.TrusteeType = TrusteeType;
	ExplicitAccess.Trustee.ptstrName = (LPWCH)TrusteeName;
	
	BOOL IsDaclPresent = FALSE;
	BOOL IsDaclDefault = FALSE;

	if (GetSecurityDescriptorDacl(RelSecurityDescriptor, &IsDaclPresent, &OldAcl, &IsDaclDefault) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_PROCESS_ACE_STATUS_RETRIEVE_DACL_FAILED;
	}

	if (SetEntriesInAclW(1, &ExplicitAccess, OldAcl, &NewAcl) != ERROR_SUCCESS) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_PROCESS_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetSecurityDescriptorDacl(NavSecurityDescriptor->AbSecurityDescriptor, TRUE, NewAcl, TRUE) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_PROCESS_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, NavSecurityDescriptor->AbSecurityDescriptor) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_PROCESS_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED;
	}

	NavFreeMem(RelSecurityDescriptor);
	return NAV_PROCESS_ACE_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavKeProtectProcess(
	IN HANDLE ProcessHandle,
	IN BOOL ProtectionState)
{
	HANDLE TokenHandle = NULL;
	if (!NAV_SUCCESS(NavOpenProcessToken(GetProcessId(ProcessHandle), &TokenHandle, NULL))) {
		return NAV_KERNEL_PROTECTION_STATUS_INVALID_TOKEN;
	}
	BOOL IsPrivilegeEnabled = FALSE;
	if (!NAV_SUCCESS(NavCheckPrivilegeToken(TokenHandle, (LPWSTR)SE_DEBUG_NAME, &IsPrivilegeEnabled))) {
		return NAV_KERNEL_PROTECTION_STATUS_PRIVILEGE_MISSING;
	}
	if (IsPrivilegeEnabled == FALSE) {
		if (!NAV_SUCCESS(NavEnableTokenPrivileges(TokenHandle, (LPWSTR)SE_DEBUG_NAME, TRUE))) {
			return NAV_KERNEL_PROTECTION_STATUS_ACCESS_DENIED;
		}
	}
	ULONG LastProcessState = ProtectionState;
	if (NT_SUCCESS(NtSetInformationProcess(ProcessHandle, NT_CRITICAL_PROCESS, &LastProcessState, sizeof(ULONG)))) {
		return NAV_KERNEL_PROTECTION_STATUS_FAILED;
	}
	return NAV_KERNEL_PROTECTION_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavKeSetFileAce(
	IN LPCWSTR FileName,
	IN ACCESS_MODE AccessMode,
	IN ACCESS_PERMISSIONS AccessPermissions,
	IN TRUSTEE_FORM TrusteeFormat,
	IN TRUSTEE_TYPE TrusteeType,
	IN LPVOID TrusteeName)
{
	DWORD BufferSize = 0;

	GetFileSecurityW(FileName, DACL_SECURITY_INFORMATION, NULL, BufferSize, &BufferSize);

	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return NAV_FILE_ACE_STATUS_UNKNOWN_BUFFER_SIZE;
	}

	PSECURITY_DESCRIPTOR RelSecurityDescriptor = (PSECURITY_DESCRIPTOR)NavAllocMem(BufferSize);

	if (RelSecurityDescriptor == FALSE) {
		return NAV_FILE_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	if (GetFileSecurityW(FileName, DACL_SECURITY_INFORMATION, RelSecurityDescriptor, BufferSize, &BufferSize) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_FILE_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	LPNAV_SECURITY_DESCRIPTOR NavSecurityDescriptor = NULL;

	NAVSTATUS AbDescriptorStatus = NavKeMakeAbDescriptor(&RelSecurityDescriptor, &NavSecurityDescriptor);

	if (!NAV_SUCCESS(AbDescriptorStatus)) {
		if (AbDescriptorStatus == NAV_MAKE_SD_STATUS_MEMORY_ALLOCATION_FAILED)
			return NAV_FILE_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
		if (AbDescriptorStatus == NAV_MAKE_SD_STATUS_UNKNOWN_SECURITY_DESCRIPTOR)
			return NAV_FILE_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	PACL NewAcl = NULL;
	PACL OldAcl = NULL;
	EXPLICIT_ACCESS_W ExplicitAccess = { 0 };
	ZeroMemory(&ExplicitAccess, sizeof(EXPLICIT_ACCESS_W));

	ExplicitAccess.grfAccessMode = AccessMode;
	ExplicitAccess.grfAccessPermissions = AccessPermissions;
	ExplicitAccess.grfInheritance = NO_INHERITANCE;
	ExplicitAccess.Trustee.TrusteeForm = TrusteeFormat;
	ExplicitAccess.Trustee.TrusteeType = TrusteeType;
	ExplicitAccess.Trustee.ptstrName = (LPWCH)TrusteeName;

	BOOL IsDaclPresent = FALSE;
	BOOL IsDaclDefault = FALSE;

	if (GetSecurityDescriptorDacl(RelSecurityDescriptor, &IsDaclPresent, &OldAcl, &IsDaclDefault) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_FILE_ACE_STATUS_RETRIEVE_DACL_FAILED;
	}

	if (SetEntriesInAclW(1, &ExplicitAccess, OldAcl, &NewAcl) != ERROR_SUCCESS) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_FILE_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetSecurityDescriptorDacl(NavSecurityDescriptor->AbSecurityDescriptor, TRUE, NewAcl, TRUE) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_FILE_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetFileSecurityW(FileName, DACL_SECURITY_INFORMATION, NavSecurityDescriptor->AbSecurityDescriptor) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_FILE_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED;
	}

	NavFreeMem(RelSecurityDescriptor);
	NavKeFreeAbDescriptor(&NavSecurityDescriptor);
	return NAV_FILE_ACE_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavKeSetKeyAce(
	IN HKEY KeyHandle,
	IN ACCESS_MODE AccessMode,
	IN ACCESS_PERMISSIONS AccessPermissions,
	IN TRUSTEE_FORM TrusteeFormat,
	IN TRUSTEE_TYPE TrusteeType,
	IN LPVOID TrusteeName)
{
	DWORD BufferSize = 0;

	if (RegGetKeySecurity(KeyHandle, DACL_SECURITY_INFORMATION, NULL, &BufferSize) != ERROR_INSUFFICIENT_BUFFER) {
		return NAV_KEY_ACE_STATUS_UNKNOWN_BUFFER_SIZE;
	}

	PSECURITY_DESCRIPTOR RelSecurityDescriptor = (PSECURITY_DESCRIPTOR)NavAllocMem(BufferSize);

	if (RelSecurityDescriptor == FALSE) {
		return NAV_KEY_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	if (RegGetKeySecurity(KeyHandle, DACL_SECURITY_INFORMATION, RelSecurityDescriptor, &BufferSize) != ERROR_SUCCESS) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_KEY_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	LPNAV_SECURITY_DESCRIPTOR NavSecurityDescriptor = NULL;

	NAVSTATUS AbDescriptorStatus = NavKeMakeAbDescriptor(&RelSecurityDescriptor, &NavSecurityDescriptor);

	if (!NAV_SUCCESS(AbDescriptorStatus)) {
		if (AbDescriptorStatus == NAV_MAKE_SD_STATUS_MEMORY_ALLOCATION_FAILED)
			return NAV_KEY_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
		if (AbDescriptorStatus == NAV_MAKE_SD_STATUS_UNKNOWN_SECURITY_DESCRIPTOR)
			return NAV_KEY_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	PACL NewAcl = NULL;
	PACL OldAcl = NULL;
	EXPLICIT_ACCESS_W ExplicitAccess = { 0 };
	ZeroMemory(&ExplicitAccess, sizeof(EXPLICIT_ACCESS_W));

	ExplicitAccess.grfAccessMode = AccessMode;
	ExplicitAccess.grfAccessPermissions = AccessPermissions;
	ExplicitAccess.grfInheritance = NO_INHERITANCE;
	ExplicitAccess.Trustee.TrusteeForm = TrusteeFormat;
	ExplicitAccess.Trustee.TrusteeType = TrusteeType;
	ExplicitAccess.Trustee.ptstrName = (LPWCH)TrusteeName;

	BOOL IsDaclPresent = FALSE;
	BOOL IsDaclDefault = FALSE;

	if (GetSecurityDescriptorDacl(RelSecurityDescriptor, &IsDaclPresent, &OldAcl, &IsDaclDefault) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_KEY_ACE_STATUS_RETRIEVE_DACL_FAILED;
	}

	if (SetEntriesInAclW(1, &ExplicitAccess, OldAcl, &NewAcl) != ERROR_SUCCESS) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_KEY_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetSecurityDescriptorDacl(NavSecurityDescriptor->AbSecurityDescriptor, TRUE, NewAcl, TRUE) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_KEY_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (RegSetKeySecurity(KeyHandle, DACL_SECURITY_INFORMATION, NavSecurityDescriptor->AbSecurityDescriptor) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavKeFreeAbDescriptor(&NavSecurityDescriptor);
		return NAV_KEY_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED;
	}

	NavFreeMem(RelSecurityDescriptor);
	NavKeFreeAbDescriptor(&NavSecurityDescriptor);
	return NAV_KEY_ACE_STATUS_SUCCESS;
}