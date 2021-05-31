// NAV Tests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#ifndef UNICODE
#define UNICODE
#endif

#pragma comment(lib, "Iphlpapi.lib")

//#include <vld.h>

#include <stdio.h>
#include <windows.h>

#include "nav/base/hook.h"


static VOID(WINAPI * TrueSleep)(DWORD dwMilliseconds) = Sleep;

VOID WINAPI TimedSleep(DWORD dwMilliseconds)
{
	printf("Hooked!");
	TrueSleep(dwMilliseconds + 50);
}

int main(void)
{
	NavHookRestoreAfterWith();
	NavHookTransactionBegin();
	NavHookUpdateThread(GetCurrentThread());
	NavHookDetourAttachFunction(&(PVOID&)TrueSleep, TimedSleep);
	NavHookTransactionCommit();

	Sleep(200);

	printf("imprimir algo");
	getchar();
	return 0;
}
