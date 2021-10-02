#pragma once

typedef unsigned long NAVSTATUS, *PNAVSTATUS, *LPNAVSTATUS;

#define NAVAPI __stdcall

#define NAV_SUCCESS(x) (((NAVSTATUS)x == 1) || ((NAVSTATUS)x >= 0x7fffffff))

#define NAV_PRIVILEGE_STATUS_FAILED							0x00UL
#define NAV_PRIVILEGE_STATUS_SUCCESS						0x01UL
#define NAV_PRIVILEGE_STATUS_NOT_ASSIGNED					0x02UL
#define NAV_PRIVILEGE_STATUS_ENABLE_FAILED					0x04UL

#define NAV_TOKEN_STATUS_FAILED								0x00UL
#define NAV_TOKEN_STATUS_SUCCESS							0x01UL
#define NAV_TOKEN_STATUS_OPEN_PROCESS_FAILED				0x02UL

#define NAV_CLOSE_TOKEN_STATUS_FAILED						0x00UL
#define NAV_CLOSE_TOKEN_STATUS_SUCCESS						0x01UL

#define NAV_CHECK_PRIVILEGE_STATUS_FAILED					0x00UL
#define NAV_CHECK_PRIVILEGE_STATUS_SUCCESS					0x01UL
#define NAV_CHECK_PRIVILEGE_STATUS_UNKNOWN_INFO				0x02UL
#define NAV_CHECK_PRIVILEGE_STATUS_UNKNOWN_LUID				0x04UL
#define NAV_CHECK_PRIVILEGE_STATUS_UNKNOWN_BUFFER_SIZE		0x08UL

#define NAV_PROCESS_ACE_STATUS_KERNEL_OBJECT_CHANGE_FAILED	0x00UL
#define NAV_PROCESS_ACE_STATUS_SUCCESS						0x01UL
#define NAV_PROCESS_ACE_STATUS_UNKNOWN_BUFFER_SIZE			0x02UL
#define NAV_PROCESS_ACE_STATUS_MEMORY_ALLOCATION_FAILED		0x04UL
#define NAV_PROCESS_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR	0x08UL
#define NAV_PROCESS_ACE_STATUS_DACL_CHANGE_FAILED			0x10UL
#define NAV_PROCESS_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED		0x20UL
#define NAV_PROCESS_ACE_STATUS_RETRIEVE_DACL_FAILED			0x40UL

#define NAV_CREATE_SID_STATUS_MEMORY_ALLOCATION_FAILED		0x00UL
#define NAV_CREATE_SID_STATUS_SUCCESS						0x01UL
#define NAV_CREATE_SID_STATUS_CREATION_FAILED				0x02UL

#define NAV_FREE_SID_STATUS_FAILED							0x00UL
#define NAV_FREE_SID_STATUS_SUCCESS							0x01UL

#define NAV_KERNEL_PROTECTION_STATUS_INVALID_TOKEN			0x00UL
#define NAV_KERNEL_PROTECTION_STATUS_SUCCESS				0x01UL
#define NAV_KERNEL_PROTECTION_STATUS_ACCESS_DENIED			0x02UL
#define NAV_KERNEL_PROTECTION_STATUS_FAILED					0x04UL
#define NAV_KERNEL_PROTECTION_STATUS_PRIVILEGE_MISSING		0x08UL

#define NAV_FILE_ACE_STATUS_KERNEL_OBJECT_CHANGE_FAILED		0x00UL
#define NAV_FILE_ACE_STATUS_SUCCESS							0x01UL
#define NAV_FILE_ACE_STATUS_UNKNOWN_BUFFER_SIZE				0x02UL
#define NAV_FILE_ACE_STATUS_MEMORY_ALLOCATION_FAILED		0x04UL
#define NAV_FILE_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR		0x08UL
#define NAV_FILE_ACE_STATUS_DACL_CHANGE_FAILED				0x10UL
#define NAV_FILE_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED		0x20UL
#define NAV_FILE_ACE_STATUS_RETRIEVE_DACL_FAILED			0x40UL

#define NAV_KEY_ACE_STATUS_KERNEL_OBJECT_CHANGE_FAILED		0x00UL
#define NAV_KEY_ACE_STATUS_SUCCESS							0x01UL
#define NAV_KEY_ACE_STATUS_UNKNOWN_BUFFER_SIZE				0x02UL
#define NAV_KEY_ACE_STATUS_MEMORY_ALLOCATION_FAILED			0x04UL
#define NAV_KEY_ACE_STATUS_UNKNOWN_SECURITY_DESCRIPTOR		0x08UL
#define NAV_KEY_ACE_STATUS_DACL_CHANGE_FAILED				0x10UL
#define NAV_KEY_ACE_STATUS_DESCRIPTOR_CHANGE_FAILED			0x20UL
#define NAV_KEY_ACE_STATUS_RETRIEVE_DACL_FAILED				0x40UL

#define NAV_MAKE_SD_STATUS_MEMORY_ALLOCATION_FAILED			0x00UL
#define NAV_MAKE_SD_STATUS_SUCCESS							0x01UL
#define NAV_MAKE_SD_STATUS_UNKNOWN_SECURITY_DESCRIPTOR		0x02UL

#define NAV_FREE_SD_STATUS_SUCCESS							0x01UL

#define NAV_CREATE_PIPE_STATUS_FAILED						0x00UL
#define NAV_CREATE_PIPE_STATUS_SUCCESS						0x01UL

#define NAV_CREATE_PROCESS_STATUS_INVALID_SESSION			0x00UL
#define NAV_CREATE_PROCESS_STATUS_SUCCESS					0x01UL
#define NAV_CREATE_PROCESS_STATUS_INVALID_USER_TOKEN		0x02UL
#define NAV_CREATE_PROCESS_STATUS_FAILED					0x04UL

#define NAV_CLOSE_PIPE_STATUS_FAILED						0x00UL
#define NAV_CLOSE_PIPE_STATUS_SUCCESS						0x01UL

#define NAV_SYSCALL_STATUS_FAILED							0x00UL
#define NAV_SYSCALL_STATUS_SUCCESS							0x01UL
#define NAV_SYSCALL_STATUS_BUFFER_OVERFLOW					0x02UL
#define NAV_SYSCALL_STATUS_MEMORY_ALLOCATION_FAILED			0x04UL

#define NAV_SYSCALL_RELEASE_STATUS_FAILED					0x00UL
#define NAV_SYSCALL_RELEASE_STATUS_SUCCESS					0x01UL

#define NAV_REGISTER_FS_FILTER_STATUS_FAILED				0x00UL
#define NAV_REGISTER_FS_FILTER_STATUS_SUCCESS				0x01UL

#define NAV_UNREGISTER_FS_FILTER_STATUS_FAILED				0x00UL
#define NAV_UNREGISTER_FS_FILTER_STATUS_SUCCESS				0x01UL

#define NAV_REGISTER_PROCESS_FILTER_STATUS_FAILED			0x00UL
#define NAV_REGISTER_PROCESS_FILTER_STATUS_SUCCESS			0x01UL

#define NAV_UNREGISTER_PROCESS_FILTER_STATUS_FAILED			0x00UL
#define NAV_UNREGISTER_PROCESS_FILTER_STATUS_SUCCESS		0x01UL

#define NAV_REGISTER_PNP_DEVICE_FILTER_STATUS_FAILED		0x00UL
#define NAV_REGISTER_PNP_DEVICE_FILTER_STATUS_SUCCESS		0x01UL

#define NAV_UNREGISTER_PNP_DEVICE_FILTER_STATUS_FAILED		0x00UL
#define NAV_UNREGISTER_PNP_DEVICE_FILTER_STATUS_SUCCESS		0x01UL

#define NAV_RETRIEVE_TCP_TABLE_STATUS_FAILED				0x00UL
#define NAV_RETRIEVE_TCP_TABLE_STATUS_SUCCESS				0x01UL

#define NAV_RELEASE_TCP_TABLE_STATUS_FAILED					0x00UL
#define NAV_RELEASE_TCP_TABLE_STATUS_SUCCESS				0x01UL

#define NAV_INJECT_LOAD_LIBRARY_ROUTINE_STATUS_FAILED		0x00UL
#define NAV_INJECT_LOAD_LIBRARY_ROUTINE_STATUS_SUCCESS		0x01UL

#define NAV_INJECT_GLOBAL_MODULE_STATUS_FAILED				0x00UL
#define NAV_INJECT_GLOBAL_MODULE_STATUS_SUCCESS				0x01UL

#define NAV_WRITE_INSTRUCTION_STATUS_FAILED					0x00UL
#define NAV_WRITE_INSTRUCTION_STATUS_SUCCESS				0x01UL

#define NAV_ALLOC_INSTRUCTION_STATUS_FAILED					0x00UL
#define NAV_ALLOC_INSTRUCTION_STATUS_SUCCESS				0x01UL

#define NAV_TRANSFER_EXECUTION_STATUS_FAILED				0x00UL
#define NAV_TRANSFER_EXECUTION_STATUS_SUCCESS				0x01UL
#define NAV_TRANSFER_EXECUTION_OPEN_STATUS_FAILED			0x02UL
#define NAV_TRANSFER_EXECUTION_SUSPEND_STATUS_FAILED		0x04UL
#define NAV_TRANSFER_EXECUTION_STATUS_UNSUPPORTED_ARCH		0x08UL
#define NAV_TRANSFER_EXECUTION_GET_CONTEXT_STATUS_FAILED	0x10UL
#define NAV_TRANSFER_EXECUTION_SET_CONTEXT_STATUS_FAILED	0x20UL
#define NAV_TRANSFER_EXECUTION_RESUME_STATUS_FAILED			0x40UL

#define NAV_RELEASE_PROCESS_ENUM_THREADS_STATUS_SUCCESS		0x01UL

#define NAV_ENUM_PROCESS_THREADS_STATUS_FAILED				0x00UL
#define NAV_ENUM_PROCESS_THREADS_STATUS_SUCCESS				0x01UL