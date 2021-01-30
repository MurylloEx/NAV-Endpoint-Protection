#include "protection.h"


NAVSTATUS NavSetProcessKernelAce(
	IN HANDLE ProcessHandle,
	IN ACCESS_MODE AccessMode,
	IN TRUSTEE_FORM TrusteeFormat,
	IN LPWSTR TrusteeName)
{
	DWORD BufferSize = 0;
	
	GetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, NULL, BufferSize, &BufferSize);
	
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
		return NAV_SET_ACE_STATUS_UNKNOWN_BUFFER_SIZE;
	}

	PSECURITY_DESCRIPTOR PSecurityDescriptor = (PSECURITY_DESCRIPTOR)malloc(BufferSize);

	if (PSecurityDescriptor == FALSE) {
		return NAV_SET_ACE_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	if (GetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, PSecurityDescriptor, BufferSize, &BufferSize) == FALSE) {
		free(PSecurityDescriptor);
		return NAV_SET_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR;
	}

	BOOL IsDaclPresent = FALSE;
	BOOL IsDaclDefault = FALSE;
	PACL OldDacl = NULL;
	PACL NewDacl = NULL;

	EXPLICIT_ACCESS_W ExplicitAccess;

	if (GetSecurityDescriptorDacl(PSecurityDescriptor, &IsDaclPresent, &OldDacl, &IsDaclDefault) == FALSE) {
		free(PSecurityDescriptor);
		return NAV_SET_ACE_STATUS_RETRIEVE_DACL_FAILED;
	}

	ZeroMemory(&ExplicitAccess, sizeof(EXPLICIT_ACCESS_W));

	ExplicitAccess.grfAccessMode = AccessMode;
	ExplicitAccess.grfAccessPermissions = PROCESS_ALL_ACCESS;
	ExplicitAccess.grfInheritance = NO_INHERITANCE;
	ExplicitAccess.Trustee.TrusteeForm = TrusteeFormat;
	ExplicitAccess.Trustee.ptstrName = TrusteeName;

	if (SetEntriesInAclW(1, &ExplicitAccess, OldDacl, &NewDacl) != ERROR_SUCCESS) {
		free(PSecurityDescriptor);
		return NAV_SET_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetSecurityDescriptorDacl(PSecurityDescriptor, TRUE, NewDacl, TRUE) == FALSE) {
		free(PSecurityDescriptor);
		return NAV_SET_ACE_STATUS_DACL_CHANGE_FAILED;
	}

	if (SetKernelObjectSecurity(ProcessHandle, DACL_SECURITY_INFORMATION, PSecurityDescriptor) == FALSE) {
		free(PSecurityDescriptor);
		return NAV_SET_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED;
	}

	free(PSecurityDescriptor);
	return NAV_SET_ACE_STATUS_SUCCESS;
}