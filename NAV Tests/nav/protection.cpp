#include "protection.h"
#include "privileges.h"

NAVSTATUS NavCreateWellKnownSid(
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
			return NAV_CREATE_SID_STATUS_SID_CREATION_FAILED;
		}
	}
	*SidPtr = PSid;
	*SidSizePtr = SidSize;
	return NAV_CREATE_SID_STATUS_SUCCESS;
}

NAVSTATUS NavFreeWellKnownSid(
	IN PSID* SidPtr)
{
	if (NavFreeMem((LPVOID)(*SidPtr)) == FALSE) {
		return NAV_FREE_SID_STATUS_FAILED;
	}
	return NAV_FREE_SID_STATUS_SUCCESS;
}

NAVSTATUS NavSetProcessKernelAce(
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
		return NAV_SET_ACE_STATUS_UNKNOWN_BUFFER_SIZE;
	}

	PSECURITY_DESCRIPTOR RelSecurityDescriptor = (PSECURITY_DESCRIPTOR)NavAllocMem(BufferSize);

	if (RelSecurityDescriptor == FALSE) {
		return NAV_SET_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	ZeroMemory(RelSecurityDescriptor, BufferSize);

	if (GetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, RelSecurityDescriptor, BufferSize, &BufferSize) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		return NAV_SET_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	DWORD AbSecurityDescriptorSize = sizeof(SECURITY_DESCRIPTOR);
	DWORD DaclSize = sizeof(ACL);
	DWORD SaclSize = sizeof(ACL);
	DWORD OwnerSidSize = sizeof(SID);
	DWORD PrimaryGroupSidSize = sizeof(SID);
	
	PSECURITY_DESCRIPTOR AbSecurityDescriptor = (PSECURITY_DESCRIPTOR)NavAllocMem(AbSecurityDescriptorSize);
	PACL Dacl = (PACL)NavAllocMem(DaclSize);
	PACL Sacl = (PACL)NavAllocMem(SaclSize);
	PSID OwnerSid = (PSID)NavAllocMem(OwnerSidSize);
	PSID PrimaryGroupSid = (PSID)NavAllocMem(PrimaryGroupSidSize);

	if (!AbSecurityDescriptor || !Dacl || !Sacl || !OwnerSid || !PrimaryGroupSid) {
		/* Free all allocated memory blocks */
		NavFreeMem(AbSecurityDescriptor);
		NavFreeMem(Dacl);
		NavFreeMem(Sacl);
		NavFreeMem(OwnerSid);
		NavFreeMem(PrimaryGroupSid);
		return NAV_SET_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	ZeroMemory(AbSecurityDescriptor, AbSecurityDescriptorSize);
	ZeroMemory(Dacl, DaclSize);
	ZeroMemory(Sacl, SaclSize);
	ZeroMemory(OwnerSid, OwnerSidSize);
	ZeroMemory(PrimaryGroupSid, PrimaryGroupSidSize);

	BOOL ConversionStatus = MakeAbsoluteSD(RelSecurityDescriptor, AbSecurityDescriptor, 
		&AbSecurityDescriptorSize, Dacl, &DaclSize,
		Sacl, &SaclSize, OwnerSid, &OwnerSidSize, 
		PrimaryGroupSid, &PrimaryGroupSidSize);

	if ((ConversionStatus == FALSE) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
		AbSecurityDescriptor = (PSECURITY_DESCRIPTOR)NavReAllocMem(
			AbSecurityDescriptor, AbSecurityDescriptorSize);
		Dacl = (PACL)NavReAllocMem(Dacl, DaclSize);
		Sacl = (PACL)NavReAllocMem(Sacl, SaclSize);
		OwnerSid = (PSID)NavReAllocMem(OwnerSid, OwnerSidSize);
		PrimaryGroupSid = (PSID)NavReAllocMem(PrimaryGroupSid, PrimaryGroupSidSize);

		if (!AbSecurityDescriptor || !Dacl || !Sacl || !OwnerSid || !PrimaryGroupSid) {
			/* Free all allocated memory blocks */
			NavFreeMem(RelSecurityDescriptor);
			NavFreeMem(AbSecurityDescriptor);
			NavFreeMem(Dacl);
			NavFreeMem(Sacl);
			NavFreeMem(OwnerSid);
			NavFreeMem(PrimaryGroupSid);
			return NAV_SET_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
		}

		ZeroMemory(AbSecurityDescriptor, AbSecurityDescriptorSize);
		ZeroMemory(Dacl, DaclSize);
		ZeroMemory(Sacl, SaclSize);
		ZeroMemory(OwnerSid, OwnerSidSize);
		ZeroMemory(PrimaryGroupSid, PrimaryGroupSidSize);

		ConversionStatus = MakeAbsoluteSD(RelSecurityDescriptor, AbSecurityDescriptor,
			&AbSecurityDescriptorSize, Dacl, &DaclSize,
			Sacl, &SaclSize, OwnerSid, &OwnerSidSize,
			PrimaryGroupSid, &PrimaryGroupSidSize);

		if (ConversionStatus == FALSE) {
			/* Free all allocated memory blocks */
			NavFreeMem(RelSecurityDescriptor);
			NavFreeMem(AbSecurityDescriptor);
			NavFreeMem(Dacl);
			NavFreeMem(Sacl);
			NavFreeMem(OwnerSid);
			NavFreeMem(PrimaryGroupSid);
			return NAV_SET_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
		}
	}

	if (ConversionStatus == FALSE) {
		/* Free all allocated memory blocks */
		NavFreeMem(RelSecurityDescriptor);
		NavFreeMem(AbSecurityDescriptor);
		NavFreeMem(Dacl);
		NavFreeMem(Sacl);
		NavFreeMem(OwnerSid);
		NavFreeMem(PrimaryGroupSid);
		return NAV_SET_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	NavFreeMem(Dacl);
	NavFreeMem(Sacl);
	NavFreeMem(OwnerSid);
	NavFreeMem(PrimaryGroupSid);

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
		NavFreeMem(AbSecurityDescriptor);
		return NAV_SET_ACE_STATUS_RETRIEVE_DACL_FAILED;
	}

	if (SetEntriesInAclW(1, &ExplicitAccess, OldAcl, &NewAcl) != ERROR_SUCCESS) {
		NavFreeMem(RelSecurityDescriptor);
		NavFreeMem(AbSecurityDescriptor);
		return NAV_SET_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetSecurityDescriptorDacl(AbSecurityDescriptor, TRUE, NewAcl, TRUE) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavFreeMem(AbSecurityDescriptor);
		return NAV_SET_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, AbSecurityDescriptor) == FALSE) {
		NavFreeMem(RelSecurityDescriptor);
		NavFreeMem(AbSecurityDescriptor);
		return NAV_SET_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED;
	}

	NavFreeMem(AbSecurityDescriptor);
	return NAV_SET_ACE_STATUS_SUCCESS;
}

NAVSTATUS NavSetProcessKernelProtection(
	IN HANDLE ProcessHandle,
	IN BOOL ProtectionState)
{
	HANDLE TokenHandle = NULL;
	if (!NAV_SUCCESS(NavOpenProcessToken(GetProcessId(ProcessHandle), &TokenHandle, NULL))) {
		return FALSE;
	}
	BOOL IsPrivilegeEnabled = FALSE;
	if (!NAV_SUCCESS(NavCheckPrivilegeToken(TokenHandle, (LPWSTR)SE_DEBUG_NAME, &IsPrivilegeEnabled))) {
		return FALSE;
	}
	if (IsPrivilegeEnabled == FALSE) {
		if (!NAV_SUCCESS(NavEnableTokenPrivileges(TokenHandle, (LPWSTR)SE_DEBUG_NAME, TRUE))) {
			return FALSE;
		}
	}
	ULONG LastProcessState = ProtectionState;
	if (NT_SUCCESS(NtSetInformationProcess(ProcessHandle, NT_CRITICAL_PROCESS, &LastProcessState, sizeof(ULONG)))) {
		return FALSE;
	}
	return TRUE;
}

NAVSTATUS NavSetFileKernelAce()
{
	return NULL;
}