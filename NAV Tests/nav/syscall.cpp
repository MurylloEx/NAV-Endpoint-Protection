#include "syscall.h"
#include <stdio.h>

typedef struct _NAV_NAMED_PIPE_DATA_SHADOW {
	HANDLE PipeHandle;
	PNAV_NAMED_PIPE_DATA PipeData;
} NAV_NAMED_PIPE_DATA_SHADOW, *PNAV_NAMED_PIPE_DATA_SHADOW;

typedef struct _NAV_NAMED_PIPE_SEMAPHORE {
	HANDLE EventHandle;
	DWORD Semaphore;
	HANDLE ThreadHandle;
	HANDLE PipeHandle;
} NAV_NAMED_PIPE_SEMAPHORE, *PNAV_NAMED_PIPE_SEMAPHORE;

DWORD WINAPI NavPipeRoutineDispatcher(LPVOID ThreadParam)
{
	PNAV_NAMED_PIPE_DATA_SHADOW PipeBufferData = (PNAV_NAMED_PIPE_DATA_SHADOW)ThreadParam;
	PNAV_NAMED_PIPE_SEMAPHORE PipeSemaphore = (PNAV_NAMED_PIPE_SEMAPHORE)PipeBufferData->PipeData->Reserved;

	DWORD IncomingBufferSize = PipeBufferData->PipeData->BufferSize;
	DWORD OutgoingBufferSize = PipeBufferData->PipeData->BufferSize;

	LPVOID IncomingAddress = NavAllocMem(IncomingBufferSize);
	LPVOID OutgoingAddress = NavAllocMem(OutgoingBufferSize);

	DWORD BufferReadBytes = 0;
	DWORD BufferWrittenBytes = 0;

	NAV_SYSCALL_INTERRUPT_REQUEST Incoming = { 0 };
	NAV_SYSCALL_INTERRUPT_RESPONSE Outgoing = { 0 };

	BOOL IsSuccess = FALSE;

	PipeSemaphore->Semaphore++;

	while (true) {
		IsSuccess = ReadFile(PipeBufferData->PipeHandle, IncomingAddress,
			PipeBufferData->PipeData->BufferSize, &BufferReadBytes, NULL);

		if (!IsSuccess || (BufferReadBytes == 0)) {
			break;
		}

		Incoming.SyscallNumber = *(ULONG_PTR*)NAV_SYSCALL_NUMBER_PTR(IncomingAddress);
		Incoming.BufferSize = *(DWORD*)NAV_SYSCALL_LENGTH_PTR(IncomingAddress);
		Incoming.BufferData = (BYTE*)NAV_SYSCALL_BUFFER_PTR(IncomingAddress);

		if (NAV_SYSCALL_TOTAL_SIZE(Incoming.BufferSize) > PipeBufferData->PipeData->BufferSize) {
			break;
		}

		Outgoing.BufferData = (BYTE*)OutgoingAddress;
		PipeBufferData->PipeData->SyscallRoutine(&Incoming, &Outgoing);
		Outgoing.BufferData = (BYTE*)OutgoingAddress;
		Outgoing.SyscallNumber = *(ULONG_PTR*)NAV_SYSCALL_NUMBER_PTR(IncomingAddress);

		if (NAV_SYSCALL_TOTAL_SIZE(Outgoing.BufferSize) > PipeBufferData->PipeData->BufferSize) {
			break;
		}

		LPVOID OutgoingBuffer = NavAllocMem(NAV_SYSCALL_TOTAL_SIZE(Outgoing.BufferSize));

		if (OutgoingBuffer == NULL) {
			break;
		}

		*(ULONG_PTR*)NAV_SYSCALL_NUMBER_PTR(OutgoingBuffer) = Outgoing.SyscallNumber;
		*(DWORD*)NAV_SYSCALL_LENGTH_PTR(OutgoingBuffer) = Outgoing.BufferSize;

		RtlCopyMemory((BYTE*)NAV_SYSCALL_BUFFER_PTR(OutgoingBuffer), Outgoing.BufferData, Outgoing.BufferSize);

		IsSuccess = WriteFile(PipeBufferData->PipeHandle, (LPCVOID)OutgoingBuffer,
			NAV_SYSCALL_TOTAL_SIZE(Outgoing.BufferSize), &BufferWrittenBytes, NULL);

		NavFreeMem(OutgoingBuffer);

		if (!IsSuccess || (PipeBufferData->PipeData->BufferSize != BufferWrittenBytes)) {
			break;
		}
	}

	NavFreeMem(PipeBufferData);
	NavFreeMem(IncomingAddress);
	NavFreeMem(OutgoingAddress);

	FlushFileBuffers(PipeBufferData->PipeHandle);
	DisconnectNamedPipe(PipeBufferData->PipeHandle);
	CloseHandle(PipeBufferData->PipeHandle);

	PipeSemaphore->Semaphore--;

	if (PipeSemaphore->Semaphore == 0)
		SetEvent(PipeSemaphore->EventHandle);

	return EXIT_SUCCESS;
}

DWORD WINAPI NavPipeThreadRoutine(LPVOID ThreadParam) {
	PNAV_NAMED_PIPE_DATA PipeData = (PNAV_NAMED_PIPE_DATA)ThreadParam;
	PNAV_NAMED_PIPE_SEMAPHORE Semaphore = (PNAV_NAMED_PIPE_SEMAPHORE)PipeData->Reserved;

	while (true) {
		HANDLE PipeHandle = INVALID_HANDLE_VALUE;
		BOOL IsConnected = FALSE;
		DWORD ThreadId = 0;
		HANDLE ThreadHandle = INVALID_HANDLE_VALUE;

		PipeHandle = CreateNamedPipeW(PipeData->PipeName, PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
			PipeData->MaxInstances, PipeData->BufferSize,
			PipeData->BufferSize, 0, PipeData->PipeSecurity);

		if (PipeHandle == INVALID_HANDLE_VALUE) {
			break;
		}

		Semaphore->PipeHandle = PipeHandle;
		IsConnected = ConnectNamedPipe(PipeHandle, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (IsConnected) {
			PNAV_NAMED_PIPE_DATA_SHADOW PipeParamsData = (PNAV_NAMED_PIPE_DATA_SHADOW)NavAllocMem(
				sizeof(NAV_NAMED_PIPE_DATA_SHADOW));
			if (PipeParamsData == NULL) {
				break;
			}
			PipeParamsData->PipeData = PipeData;
			PipeParamsData->PipeHandle = PipeHandle;
			ThreadHandle = CreateThread(PipeData->ThreadSecurity, NULL,
				NavPipeRoutineDispatcher, PipeParamsData, NULL, &ThreadId);
			if (ThreadHandle == NULL) {
				NavFreeMem(PipeParamsData);
				break;
			}
			ResetEvent(((PNAV_NAMED_PIPE_SEMAPHORE)PipeData->Reserved)->EventHandle);
			CloseHandle(ThreadHandle);
		}
		else {
			CloseHandle(PipeHandle);
		}
	}

	return EXIT_SUCCESS;
}

NAVSTATUS NAVAPI NavCreateNamedPipe(
	IN PNAV_NAMED_PIPE_DATA PipeData,
	OUT PDWORD ThreadId) {
	HANDLE ThreadHandle = CreateThread(PipeData->ThreadSecurity, NULL,
		(LPTHREAD_START_ROUTINE)NavPipeThreadRoutine, (LPVOID)PipeData, NULL, ThreadId);
	if (ThreadHandle != NULL) {
		PNAV_NAMED_PIPE_SEMAPHORE Semaphore = 
			(PNAV_NAMED_PIPE_SEMAPHORE)NavAllocMem(sizeof(NAV_NAMED_PIPE_SEMAPHORE));
		Semaphore->EventHandle = CreateEventW(NULL, FALSE, TRUE, NULL);
		Semaphore->ThreadHandle = ThreadHandle;
		PipeData->Reserved = (LPVOID)Semaphore;
		return NAV_CREATE_PIPE_STATUS_SUCCESS;
	}
	return NAV_CREATE_PIPE_STATUS_FAILED;
}

NAVSTATUS NAVAPI NavDeleteNamedPipe(
	IN PNAV_NAMED_PIPE_DATA PipeData)
{
	PNAV_NAMED_PIPE_SEMAPHORE Semaphore = (PNAV_NAMED_PIPE_SEMAPHORE)PipeData->Reserved;
	if (WaitForSingleObject(Semaphore->EventHandle, INFINITE) == WAIT_OBJECT_0) {
		if (TerminateThread(Semaphore->ThreadHandle, EXIT_SUCCESS) != FALSE) {
			NavFreeMem(Semaphore);
			NavFreeMem(PipeData);
			DisconnectNamedPipe(Semaphore->PipeHandle);
			CloseHandle(Semaphore->PipeHandle);
			return NAV_CLOSE_PIPE_STATUS_SUCCESS;
		}
	}
	return NAV_CLOSE_PIPE_STATUS_FAILED;
}

NAVSTATUS NAVAPI NavSyscallExecute(
	IN LPCWSTR PipeName,
	IN LPSECURITY_ATTRIBUTES PipeSecurity,
	IN BYTE* Buffer,
	IN DWORD Size,
	IN DWORD SyscallBufferSize,
	IN ULONG_PTR SyscallNumber,
	OUT PNAV_SYSCALL_INTERRUPT_RESPONSE Response)
{
	HANDLE PipeHandle = CreateFileW(PipeName, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ, PipeSecurity, OPEN_EXISTING, NULL, NULL);

	BOOL Status = FALSE;
	LPVOID ReallocBuffer = NULL;
	DWORD BufferWrittenBytes = 0;
	DWORD BufferReadBytes = 0;
	DWORD PipeMode = PIPE_READMODE_MESSAGE;

	if (SetNamedPipeHandleState(PipeHandle, &PipeMode, NULL, NULL) == FALSE) {
		return NAV_SYSCALL_STATUS_FAILED;
	}

	if (NAV_SYSCALL_TOTAL_SIZE(Size) > SyscallBufferSize) {
		return NAV_SYSCALL_STATUS_BUFFER_OVERFLOW;
	}

	ReallocBuffer = NavAllocMem(NAV_SYSCALL_TOTAL_SIZE(Size));

	if (ReallocBuffer == NULL) {
		CloseHandle(PipeHandle);
		return NAV_SYSCALL_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	*(ULONG_PTR*)NAV_SYSCALL_NUMBER_PTR(ReallocBuffer) = SyscallNumber;
	*(DWORD*)NAV_SYSCALL_LENGTH_PTR(ReallocBuffer) = Size;

	RtlCopyMemory((BYTE*)NAV_SYSCALL_BUFFER_PTR(ReallocBuffer), Buffer, Size);

	Status = WriteFile(PipeHandle, (LPCVOID)ReallocBuffer, NAV_SYSCALL_TOTAL_SIZE(Size), &BufferWrittenBytes, NULL);

	if (Status == FALSE) {
		NavFreeMem(ReallocBuffer);
		CloseHandle(PipeHandle);
		return NAV_SYSCALL_STATUS_FAILED;
	}

	FlushFileBuffers(PipeHandle);
	ReallocBuffer = NavReAllocMem(ReallocBuffer, SyscallBufferSize);

	if (ReallocBuffer == NULL) {
		CloseHandle(PipeHandle);
		return NAV_SYSCALL_STATUS_MEMORY_ALLOCATION_FAILED;
	}

	do {
		Status = ReadFile(PipeHandle, ReallocBuffer, NAV_SYSCALL_BUFFER_SIZE(SyscallBufferSize), 
			&BufferReadBytes, NULL);
		if (!Status && (GetLastError() != ERROR_MORE_DATA))
			break;
	} while (!Status);

	RtlZeroMemory(Response, sizeof(NAV_SYSCALL_INTERRUPT_RESPONSE));

	Response->BufferData = (BYTE*)NAV_SYSCALL_BUFFER_PTR(ReallocBuffer);
	Response->BufferSize = *(DWORD*)NAV_SYSCALL_LENGTH_PTR(ReallocBuffer);
	Response->SyscallNumber = *(ULONG_PTR*)NAV_SYSCALL_NUMBER_PTR(ReallocBuffer);

	CloseHandle(PipeHandle);
	return NAV_SYSCALL_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavSyscallRelease(
	IN PNAV_SYSCALL_INTERRUPT_RESPONSE Response)
{
	if (NavFreeMem(NAV_SYSCALL_BASE_PTR(Response->BufferData)) == NULL) {
		return NAV_SYSCALL_RELEASE_STATUS_FAILED;
	}
	return NAV_SYSCALL_RELEASE_STATUS_SUCCESS;
}