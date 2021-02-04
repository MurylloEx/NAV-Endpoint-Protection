#pragma once

#include "status.h"
#include "memory.h"

#define NAV_PIPE_BUFFER_SIZE 65536

#define NAV_SYSCALL_BUFFER_SIZE(Size) ((DWORD)Size - (sizeof(DWORD) + sizeof(ULONG_PTR)))
#define NAV_SYSCALL_TOTAL_SIZE(Size) ((DWORD)Size + (sizeof(DWORD) + sizeof(ULONG_PTR)))

typedef struct _NAV_SYSCALL_INTERRUPT_RESPONSE {
	ULONG_PTR SyscallNumber;
	DWORD BufferSize;
	BYTE* BufferData;
} NAV_SYSCALL_INTERRUPT_RESPONSE, *PNAV_SYSCALL_INTERRUPT_RESPONSE;

typedef struct _NAV_SYSCALL_INTERRUPT_REQUEST {
	ULONG_PTR SyscallNumber;
	DWORD BufferSize;
	BYTE* BufferData;
} NAV_SYSCALL_INTERRUPT_REQUEST, *PNAV_SYSCALL_INTERRUPT_REQUEST;

typedef VOID(NAVAPI *LPNAV_SYSCALL_ROUTINE)(
	IN PNAV_SYSCALL_INTERRUPT_REQUEST Incoming,
	OUT PNAV_SYSCALL_INTERRUPT_RESPONSE Outgoing);

typedef struct _NAV_NAMED_PIPE_DATA {
	LPCWSTR PipeName;
	DWORD MaxInstances;
	DWORD BufferSize;
	LPSECURITY_ATTRIBUTES ThreadSecurity;
	LPSECURITY_ATTRIBUTES PipeSecurity;
	LPNAV_SYSCALL_ROUTINE SyscallRoutine;
	LPVOID Reserved;
} NAV_NAMED_PIPE_DATA, *PNAV_NAMED_PIPE_DATA;

NAVSTATUS NAVAPI NavCreateNamedPipe(
	IN PNAV_NAMED_PIPE_DATA PipeData,
	OUT PDWORD ThreadId);
