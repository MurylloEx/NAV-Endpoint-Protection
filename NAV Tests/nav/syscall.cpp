#include "syscall.h"

typedef struct _NAV_NAMED_PIPE_DATA_SHADOW {
	HANDLE PipeHandle;
	PNAV_NAMED_PIPE_DATA PipeData;
} NAV_NAMED_PIPE_DATA_SHADOW, *PNAV_NAMED_PIPE_DATA_SHADOW;

typedef struct _NAV_NAMED_PIPE_SEMAPHORE {
	HANDLE EventHandle;
	DWORD Semaphore;
	HANDLE ThreadHandle;
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

		Incoming.SyscallNumber = *(ULONG_PTR*)IncomingAddress;
		Incoming.BufferSize = *(DWORD*)((ULONG_PTR)IncomingAddress + sizeof(ULONG_PTR));
		Incoming.BufferData = (BYTE*)((ULONG_PTR)IncomingAddress + sizeof(ULONG_PTR) + sizeof(DWORD));

		if (NAV_SYSCALL_TOTAL_SIZE(Incoming.BufferSize) > PipeBufferData->PipeData->BufferSize) {
			break;
		}

		Outgoing.BufferData = (BYTE*)OutgoingAddress;
		PipeBufferData->PipeData->SyscallRoutine(&Incoming, &Outgoing);
		Outgoing.SyscallNumber = *(ULONG_PTR*)IncomingAddress;

		if (NAV_SYSCALL_TOTAL_SIZE(Outgoing.BufferSize) > PipeBufferData->PipeData->BufferSize) {
			break;
		}

		IsSuccess = WriteFile(PipeBufferData->PipeHandle, (LPCVOID)OutgoingAddress,
			PipeBufferData->PipeData->BufferSize, &BufferWrittenBytes, NULL);

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
		PNAV_NAMED_PIPE_SEMAPHORE Semaphore = (PNAV_NAMED_PIPE_SEMAPHORE)NavAllocMem(sizeof(NAV_NAMED_PIPE_SEMAPHORE));
		Semaphore->EventHandle = CreateEventW(NULL, FALSE, TRUE, NULL);
		Semaphore->ThreadHandle = ThreadHandle;
		return NAV_CREATE_PIPE_STATUS_SUCCESS;
	}
	return NAV_CREATE_PIPE_STATUS_FAILED;
}

NAVSTATUS NAVAPI NavDeleteNamedPipe(
	IN PNAV_NAMED_PIPE_DATA PipeData)
{
	PNAV_NAMED_PIPE_SEMAPHORE PipeSemaphore = (PNAV_NAMED_PIPE_SEMAPHORE)PipeData->Reserved;
	if (WaitForSingleObject(PipeSemaphore->EventHandle, INFINITE) == WAIT_OBJECT_0) {
		if (TerminateThread(PipeSemaphore->ThreadHandle, EXIT_SUCCESS) != FALSE) {
			NavFreeMem(PipeSemaphore);
			NavFreeMem(PipeData);
			return NAV_CLOSE_PIPE_STATUS_SUCCESS;
		}
	}
	return NAV_CLOSE_PIPE_STATUS_FAILED;
}