// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#include <vld.h>
#include <stdio.h>
#include "nav/syscall.h"

VOID NAVAPI NavSyscallRoutine(
	IN PNAV_SYSCALL_INTERRUPT_REQUEST Incoming, 
	OUT PNAV_SYSCALL_INTERRUPT_RESPONSE Outgoing) 
{
	//printf("%p\n", Incoming->BufferData);
	Outgoing->BufferSize = 65530;
	FillMemory(Outgoing->BufferData, 65500, 0xcc);
}



VOID Tests() {

	PNAV_NAMED_PIPE_DATA data = (PNAV_NAMED_PIPE_DATA)NavAllocMem(sizeof(NAV_NAMED_PIPE_DATA));
	DWORD threadId = 0;

	data->BufferSize = NAV_PIPE_BUFFER_SIZE;
	data->MaxInstances = PIPE_UNLIMITED_INSTANCES;
	data->ThreadSecurity = NULL;
	data->PipeSecurity = NULL;
	data->PipeName = L"\\\\.\\pipe\\NAV_NAMED_PIPE";

	data->SyscallRoutine = NavSyscallRoutine;

	NavCreateNamedPipe(data, &threadId);

	BYTE* buffer = (BYTE*)NavAllocMem(20);
	for (ULONG i = 0; i < 20; i++) {
		buffer[i] = (BYTE)i;
	}

	Sleep(200);

	NAV_SYSCALL_INTERRUPT_RESPONSE response = { 0 };

	NavSyscallExecute(L"\\\\.\\pipe\\NAV_NAMED_PIPE", NULL, buffer, 20, NAV_PIPE_BUFFER_SIZE, 76666, &response);

	getchar();
	NavDeleteNamedPipe(data);
}

int main(VOID)
{
	Tests();
	
	return 0;
}
