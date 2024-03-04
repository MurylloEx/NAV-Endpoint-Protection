#include "nav/base/pipe.h"
#include <stdio.h>

VOID WINAPI OnReceive(PNAV_PIPE_MESSAGE Request, PNAV_PIPE_MESSAGE Response) {
	Response->Size = 5 * sizeof(BYTE);
	Response->Buffer = (BYTE*)malloc(Response->Size);

	if (Response->Buffer == NULL) {
		return;
	}

	memset(Response->Buffer, NULL, Response->Size);
	memcpy_s(Response->Buffer, Response->Size, new BYTE[5]{ 0x11, 0x22, 0x33, 0x44, 0x55 }, Response->Size);
}

VOID WINAPI OnRelease(PNAV_PIPE_MESSAGE Response) {
	free(Response->Buffer);
}


int main(void) {
	NAV_PIPE_SERVER Server = { 0 };

	Server.Name = L"\\\\.\\Pipe\\MySamplePipe";
	Server.BufferSize = 1024;
	Server.RequestHandler = OnReceive;
	Server.ReleaseHandler = OnRelease;
	Server.MaxInstances = PIPE_UNLIMITED_INSTANCES;

	NAV_PIPE_MESSAGE response = { 0 };
	BYTE* buffer = (BYTE*)malloc(2048);
	
	NAV_HANDLE handle = NavCreateNamedPipeServer(&Server);

	NavSendNamedPipeBuffer(L"\\\\.\\Pipe\\MySamplePipe", NULL, buffer, 2048, &response);
	NavCloseNamedPipeServer(handle);
}

