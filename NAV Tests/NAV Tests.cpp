#ifndef UNICODE
#define UNICODE
#endif

#include "nav/base/winapi.h"
#include "nav/base/status.h"
#include "nav/base/memory.h"
#include "nav/base/injection.h"
#include <TlHelp32.h>
#include <stdio.h>
//#include <vld.h>

#define TARGET_PROCESS 5320


int main(void){
	LPCWSTR dllName = L"C:\\users\\murilo\\desktop\\zwquerysysteminformation\\outros\\assembly\\dllexample_x86.dll";
	NAVSTATUS res = NavExecuteRemoteInstruction(TARGET_PROCESS, dllName, LoadLibraryW, NAVX86);

	getchar();
	return 0;
}
