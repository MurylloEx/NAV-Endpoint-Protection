// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

//#include <vld.h>
#include <stdio.h>
#include "nav/syscall.h"

VOID NAVAPI NavSyscallRoutine(
	IN PNAV_SYSCALL_INTERRUPT_REQUEST Incoming, 
	OUT PNAV_SYSCALL_INTERRUPT_RESPONSE Outgoing) 
{
	wprintf(L"wtf\n");
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

	NAVSTATUS status = NavCreateNamedPipe(data, &threadId);
	getchar();

	NavFreeMem(data);
}


int main(VOID)
{
	Tests();
	
	return 0;
}
