#include "pipe.h"

typedef struct _NAV_PIPE_SERVER_THREAD {
	PNAV_PIPE_SERVER Configuration;
	DWORD ServerThreadId;
	BOOL IsCancelationPending;
	DWORD NumberOfActiveInstances;
	HANDLE ActiveInstancesLockEventHandle;
	HANDLE CancelationCompletedEventHandle;
} NAV_PIPE_SERVER_THREAD, * PNAV_PIPE_SERVER_THREAD;

typedef struct _NAV_PIPE_INSTANCE {
	HANDLE PipeHandle;
	HANDLE InstanceThreadHandle;
	DWORD InstanceThreadId;
	PNAV_PIPE_SERVER_THREAD ServerThread;
} NAV_PIPE_INSTANCE, * PNAV_PIPE_INSTANCE;

VOID WINAPI AcquireNamedPipeLock(PNAV_PIPE_SERVER_THREAD ServerThread) {
	ServerThread->NumberOfActiveInstances++;
	ResetEvent(ServerThread->ActiveInstancesLockEventHandle);
}

VOID WINAPI ReleaseNamedPipeLock(PNAV_PIPE_SERVER_THREAD ServerThread) {
	ServerThread->NumberOfActiveInstances--;
	if (ServerThread->NumberOfActiveInstances == 0) {
		SetEvent(ServerThread->ActiveInstancesLockEventHandle);
	}
}

BOOL WINAPI CheckForNamedPipeCancelation(PNAV_PIPE_SERVER_THREAD ServerThread) {
	if (ServerThread->IsCancelationPending == TRUE) {
		if (WaitForSingleObject(ServerThread->ActiveInstancesLockEventHandle, INFINITE) == WAIT_OBJECT_0) {
			return TRUE;
		}
	}
	return FALSE;
}

DWORD WINAPI NavNamedPipeDispatcher(LPVOID Parameter) {
	PNAV_PIPE_INSTANCE PipeInstance = (PNAV_PIPE_INSTANCE)Parameter;
	PNAV_PIPE_SERVER_THREAD ServerThread = PipeInstance->ServerThread;
	PNAV_PIPE_SERVER Configuration = ServerThread->Configuration;
	AcquireNamedPipeLock(ServerThread);

	DWORD NumberOfBytesAvailable = 0;
	DWORD NumberOfReadBytes = 0;
	DWORD NumberOfWrittenBytes = 0;
	PVOID ReceivedBuffer = NULL;
	NAV_PIPE_MESSAGE Request = { 0 };
	NAV_PIPE_MESSAGE Response = { 0 };

	if (!PeekNamedPipe(PipeInstance->PipeHandle, NULL, NULL, NULL, &NumberOfBytesAvailable, NULL)) {
		goto CLEANUP;
	}

	ReceivedBuffer = NavAllocate(NumberOfBytesAvailable);

	if (!ReceivedBuffer) {
		goto CLEANUP;
	}

	if (!ReadFile(PipeInstance->PipeHandle, ReceivedBuffer, NumberOfBytesAvailable, &NumberOfReadBytes, NULL)) {
		if (GetLastError() != ERROR_MORE_DATA) {
			goto CLEANUP;
		}
	}

	Request.Buffer = (BYTE*)ReceivedBuffer;
	Request.Size = NumberOfBytesAvailable;

	Configuration->RequestHandler(&Request, &Response);

	NavFree(ReceivedBuffer);

	if ((Response.Buffer == NULL) || (Response.Size == 0)) {
		goto CLEANUP;
	}

	if (!WriteFile(PipeInstance->PipeHandle, (LPCVOID)Response.Buffer, Response.Size, &NumberOfWrittenBytes, NULL)) {
		goto CLEANUP;
	}

	FlushFileBuffers(PipeInstance->PipeHandle);

	Configuration->ReleaseHandler(&Response);
CLEANUP:
	DisconnectNamedPipe(PipeInstance->PipeHandle);
	CloseHandle(PipeInstance->PipeHandle);
	CloseHandle(PipeInstance->InstanceThreadHandle);
	ReleaseNamedPipeLock(ServerThread);
	NavFree(Parameter);
	return EXIT_SUCCESS;
}

DWORD WINAPI NavNamedPipeRoutine(LPVOID Parameter) {
	PNAV_PIPE_SERVER_THREAD ServerThread = (PNAV_PIPE_SERVER_THREAD)Parameter;
	PNAV_PIPE_SERVER Configuration = ServerThread->Configuration;

	while (TRUE) {
		HANDLE PipeHandle = CreateNamedPipeW(
			Configuration->Name,
			PIPE_ACCESS_DUPLEX,
			PIPE_WAIT | PIPE_READMODE_MESSAGE | PIPE_TYPE_MESSAGE,
			Configuration->MaxInstances,
			Configuration->BufferSize,
			Configuration->BufferSize,
			Configuration->DefaultTimeout,
			Configuration->PipeSecurity);

		if (WaitForSingleObject(Configuration->IsPipeReadyEventHandle, NULL) != WAIT_OBJECT_0) {
			SetEvent(Configuration->IsPipeReadyEventHandle);
		}

		if (PipeHandle == INVALID_HANDLE_VALUE) {
			return EXIT_FAILURE;
		}

		BOOL IsConnected = ConnectNamedPipe(PipeHandle, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (IsConnected) {
			PNAV_PIPE_INSTANCE PipeInstance = (PNAV_PIPE_INSTANCE)NavAllocate(sizeof(NAV_PIPE_INSTANCE));

			if (!PipeInstance) {
				DisconnectNamedPipe(PipeHandle);
				CloseHandle(PipeHandle);

				continue;
			}

			PipeInstance->PipeHandle = PipeHandle;
			PipeInstance->ServerThread = ServerThread;
			PipeInstance->InstanceThreadHandle = CreateThread(
				Configuration->ThreadSecurity, NULL,
				NavNamedPipeDispatcher,
				(LPVOID)PipeInstance, NULL,
				&PipeInstance->InstanceThreadId);
		}
		else {
			CloseHandle(PipeHandle);
		}

		if (CheckForNamedPipeCancelation(ServerThread) == TRUE) {
			break;
		}
	}

	CloseHandle(ServerThread->ActiveInstancesLockEventHandle);
	CloseHandle(Configuration->IsPipeReadyEventHandle);

	SetEvent(ServerThread->CancelationCompletedEventHandle);

	return EXIT_SUCCESS;
}

NAV_HANDLE WINAPI NavCreateNamedPipeServer(PNAV_PIPE_SERVER Configuration) {
	PNAV_PIPE_SERVER_THREAD ServerThread = (PNAV_PIPE_SERVER_THREAD)NavAllocate(sizeof(NAV_PIPE_SERVER_THREAD));

	if (!ServerThread) {
		return NULL;
	}

	ServerThread->Configuration = Configuration;
	ServerThread->IsCancelationPending = FALSE;
	ServerThread->NumberOfActiveInstances = 0;
	ServerThread->ActiveInstancesLockEventHandle = CreateEventW(NULL, FALSE, FALSE, NULL);
	ServerThread->CancelationCompletedEventHandle = CreateEventW(NULL, FALSE, FALSE, NULL);
	ServerThread->Configuration->IsPipeReadyEventHandle = CreateEventW(NULL, FALSE, FALSE, NULL);

	if (!ServerThread->Configuration->IsPipeReadyEventHandle || !ServerThread->ActiveInstancesLockEventHandle) {
		NavFree(ServerThread);
		return NULL;
	}

	HANDLE ThreadHandle = CreateThread(
		Configuration->ThreadSecurity, NULL,
		NavNamedPipeRoutine,
		(LPVOID)ServerThread,
		NULL, &ServerThread->ServerThreadId);

	if (!ThreadHandle) {
		NavFree(ServerThread);
		return NULL;
	}

	CloseHandle(ThreadHandle);

	WaitForSingleObject(Configuration->IsPipeReadyEventHandle, INFINITE);

	return (NAV_HANDLE)ServerThread;
}

BOOL WINAPI NavCloseNamedPipeServer(NAV_HANDLE NavPipeHandle) {
	if (!NavPipeHandle) {
		return FALSE;
	}

	PNAV_PIPE_SERVER_THREAD ServerThread = (PNAV_PIPE_SERVER_THREAD)NavPipeHandle;
	ServerThread->IsCancelationPending = TRUE;

	if (WaitForSingleObject(ServerThread->CancelationCompletedEventHandle, INFINITE) == WAIT_OBJECT_0) {
		ServerThread->IsCancelationPending = FALSE;
		NavFree(ServerThread);
		return TRUE;
	}

	return FALSE;
}

BOOL WINAPI NavWriteNamedPipeBuffer(HANDLE PipeHandle, BYTE* Buffer, DWORD Size) {
	DWORD NumberOfWrittenBytes = 0;

	if (!WriteFile(PipeHandle, (LPCVOID)Buffer, Size, &NumberOfWrittenBytes, NULL)) {
		return FALSE;
	}

	FlushFileBuffers(PipeHandle);

	return TRUE;
}

BOOL WINAPI NavReadNamedPipeBuffer(HANDLE PipeHandle, BYTE** Buffer, DWORD* Size) {
	DWORD NumberOfBytesAvailable = 0;
	DWORD NumberOfReadBytes = 0;

	// This trick forces the PeekNamedPipe to work properly below.
	if (!ReadFile(PipeHandle, NULL, 0, NULL, NULL)) {
		if (GetLastError() != ERROR_MORE_DATA) {
			return FALSE;
		}
	}

	if (!PeekNamedPipe(PipeHandle, NULL, NULL, NULL, &NumberOfBytesAvailable, &NumberOfBytesAvailable)) {
		return FALSE;
	}

	PVOID ReceivedBuffer = NavAllocate(NumberOfBytesAvailable);

	if (!ReceivedBuffer) {
		return FALSE;
	}

	if (!ReadFile(PipeHandle, (LPVOID)ReceivedBuffer, NumberOfBytesAvailable, &NumberOfReadBytes, NULL)) {
		if (GetLastError() != ERROR_MORE_DATA) {
			NavFree(ReceivedBuffer);
			return FALSE;
		}
	}

	*Buffer = (BYTE*)ReceivedBuffer;
	*Size = NumberOfBytesAvailable;

	return TRUE;
}

BOOL WINAPI NavSendNamedPipeBuffer(
	LPCWSTR PipeName,
	LPSECURITY_ATTRIBUTES PipeSecurity,
	BYTE* Buffer,
	DWORD Size,
	PNAV_PIPE_MESSAGE Response) 
{
	HANDLE PipeHandle = CreateFileW(PipeName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, PipeSecurity, OPEN_EXISTING, NULL, NULL);

	if (PipeHandle == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	DWORD PipeMode = PIPE_READMODE_MESSAGE;

	if (!SetNamedPipeHandleState(PipeHandle, &PipeMode, NULL, NULL)) {
		CloseHandle(PipeHandle);
		return FALSE;
	}

	if (!NavWriteNamedPipeBuffer(PipeHandle, Buffer, Size)) {
		CloseHandle(PipeHandle);
		return FALSE;
	}

	if (!NavReadNamedPipeBuffer(PipeHandle, &Response->Buffer, &Response->Size)) {
		CloseHandle(PipeHandle);
		return FALSE;
	}

	CloseHandle(PipeHandle);
	return TRUE;
}
