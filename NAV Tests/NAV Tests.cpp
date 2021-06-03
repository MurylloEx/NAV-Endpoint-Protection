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
#include "nav/base/wmi.h"
#include "nav/base/minifilters.h"

ULONG __stdcall Soma(ULONG a, ULONG b) {
	return a + b;
}

static ULONG (__stdcall *OriginalSoma)(ULONG a, ULONG b) = Soma;

ULONG __stdcall SomaAdulterada(ULONG a, ULONG b) {
	return OriginalSoma(a, b) + 5;
}

VOID FilterCallback(NAV_PNP_DEVICE_DATA Data, NAV_PNP_DEVICE_NOTIFY_TYPE NotifyType)
{
	if (NotifyType == NAV_PNP_DEVICE_NOTIFY_TYPE::TYPE_INSERT) {
		wprintf(L"%s - %s\n", L"Inserted", Data.DriveName);
	}
	else {
		wprintf(L"%s - %s\n", L"Removed", Data.DriveName);
	}
}

VOID FilterCallback2(NAV_PROCESS_DATA Data, NAV_PROCESS_NOTIFY_TYPE NotifyType)
{
	if (NotifyType == NAV_PROCESS_NOTIFY_TYPE::TYPE_CREATION) {
		wprintf(L"%s - %s with Pid: %d\n", L"Created", Data.ProcessName, Data.ProcessId);
	}
	else {
		wprintf(L"%s with Pid: %d\n", L"Terminated", Data.ProcessId);
	}
	
}

int main(void)
{
	PNAV_PNP_DEVICE_FILTER Filter;

	NavRegisterPnpDeviceFilter(FilterCallback, &Filter);

	PNAV_PROCESS_FILTER Filter2;

	NavRegisterProcessFilter(FilterCallback2, &Filter2);


	//NAVSTATUS result = NavUnregisterProcessFilter(PsFilter);

	getchar();
	return 0;
}
