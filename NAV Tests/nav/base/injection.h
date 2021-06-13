#pragma once

#include "status.h"
#include "winapi.h"

typedef VOID(NAVAPI *PNAV_TRANSFER_EXECUTION_CALLBACK)(
	IN ULONG_PTR InstructionPointer,
	OUT ULONG_PTR* NewInstructionPointer,
	IN LPVOID Arguments,
	OUT NAVSTATUS* Status);

typedef struct _NAV_THREAD_INFORMATION {
	DWORD ProcessId;
	DWORD ThreadId;
	LPVOID NextOffset;
} NAV_THREAD_INFORMATION, *PNAV_THREAD_INFORMATION;

typedef struct _NAV_EXECUTION_ARGUMENTS {
	DWORD Architecture;
	HANDLE ProcessHandle;
	LPVOID LoaderAddress;
	LPVOID ModulePathAddress;
	BYTE* RemoteInstructionBuffer;
	BYTE* InstructionBuffer;
	SIZE_T InstructionBufferSize;
	SIZE_T InstructionWrittenBytes;
} NAV_EXECUTION_ARGUMENTS, *PNAV_EXECUTION_ARGUMENTS;

NAVSTATUS NAVAPI NavInjectLoadLibraryRoutine(
	IN DWORD ProcessId,
	IN LPWSTR ModulePath,
	OUT HANDLE* ThreadHandle);

NAVSTATUS NAVAPI NavInjectGlobalModule(
	IN LPWSTR ModulePath,
	IN LPSTR Procedure,
	OUT HHOOK* HookHandle);

NAVSTATUS NAVAPI NavEnumProcessThreads(
	IN DWORD ProcessId,
	OUT PNAV_THREAD_INFORMATION* ThreadInformation,
	OUT LPDWORD NumberOfThreads);

NAVSTATUS NAVAPI NavWriteInstruction(
	IN HANDLE ProcessHandle,
	IN BYTE* PageAddress,
	IN BYTE* InstructionBuffer,
	IN SIZE_T InstructionBufferSize,
	OUT SIZE_T* NumberOfBytesWritten);

NAVSTATUS NAVAPI NavAllocInstruction(
	IN HANDLE ProcessHandle,
	IN SIZE_T InstructionBufferSize,
	OUT BYTE** RemoteBuffer);

NAVSTATUS NAVAPI NavTransferExecution(
	IN PNAV_TRANSFER_EXECUTION_CALLBACK Callback,
	IN PNAV_EXECUTION_ARGUMENTS Arguments,
	IN DWORD ThreadId,
	IN DWORD Architecture);

NAVSTATUS NAVAPI NavReleaseEnumProcessThreads(
	IN PNAV_THREAD_INFORMATION ThreadInformation,
	IN DWORD NumberOfThreads);

NAVSTATUS NAVAPI NavExecuteRemoteInstruction(
	IN DWORD ProcessId,
	IN LPCWSTR ModulePath,
	IN LPVOID LoaderAddress,
	IN DWORD Architecture);