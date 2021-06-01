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

ULONG __stdcall Soma(ULONG a, ULONG b) {
	return a + b;
}

static ULONG (__stdcall *OriginalSoma)(ULONG a, ULONG b) = Soma;

ULONG __stdcall SomaAdulterada(ULONG a, ULONG b) {
	return OriginalSoma(a, b) + 5;
}

int main(void)
{
	NavHookRestoreAfterWith();
	NavHookTransactionBegin();
	NavHookUpdateThread(GetCurrentThread());
	NavHookDetourAttachFunction(&(PVOID&)OriginalSoma, SomaAdulterada);
	NavHookTransactionCommit();

	printf("Resultado da soma: %d", Soma(1, 2));
	getchar();
	return 0;
}
