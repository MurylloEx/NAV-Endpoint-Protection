#pragma once

#include "status.h"
#include "memory.h"

typedef PVOID NAV_HANDLE;

typedef struct _NAV_PIPE_MESSAGE {
	BYTE* Buffer;
	DWORD Size;
} NAV_PIPE_MESSAGE, * PNAV_PIPE_MESSAGE;

typedef VOID(WINAPI* PNAV_PIPE_SERVER_HANDLER)(PNAV_PIPE_MESSAGE Request, PNAV_PIPE_MESSAGE Response);
typedef VOID(WINAPI* PNAV_PIPE_RELEASE_HANDLER)(PNAV_PIPE_MESSAGE Response);

typedef struct _NAV_PIPE_SERVER {
	LPCWSTR Name;
	DWORD MaxInstances;
	DWORD DefaultTimeout;
	DWORD BufferSize;
	HANDLE IsPipeReadyEventHandle;
	PNAV_PIPE_SERVER_HANDLER RequestHandler;
	PNAV_PIPE_RELEASE_HANDLER ReleaseHandler;
	LPSECURITY_ATTRIBUTES PipeSecurity;
	LPSECURITY_ATTRIBUTES ThreadSecurity;
} NAV_PIPE_SERVER, * PNAV_PIPE_SERVER;

NAV_HANDLE WINAPI NavCreateNamedPipeServer(PNAV_PIPE_SERVER Configuration);

BOOL WINAPI NavCloseNamedPipeServer(NAV_HANDLE NavPipeHandle);

BOOL WINAPI NavSendNamedPipeBuffer(
	LPCWSTR PipeName,
	LPSECURITY_ATTRIBUTES PipeSecurity,
	BYTE* Buffer,
	DWORD Size,
	PNAV_PIPE_MESSAGE Response);
