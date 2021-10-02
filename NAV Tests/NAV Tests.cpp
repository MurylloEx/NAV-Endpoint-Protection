#ifndef UNICODE
#define UNICODE
#endif


#include "nav/base/winapi.h"
#include "nav/base/status.h"
#include "nav/base/memory.h"
#include "nav/base/loader.h"
#include <TlHelp32.h>
#include <stdio.h>
//#include <vld.h>


typedef NTSYSAPI NTSTATUS (NTAPI *PLdrLoadDll)(
	IN PWCHAR               PathToFile OPTIONAL, 
	IN ULONG                Flags OPTIONAL, 
	IN PUNICODE_STRING      ModuleFileName, 
	OUT PHANDLE             ModuleHandle); 


#define TARGET_PROCESS 0x12b4


VOID NAVAPI SwitchContextCallbackX64(LPVOID Context, HANDLE hThread, DWORD ProcessId, DWORD64 *Rip) {
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	
	LPVOID pRtlInitUnicodeString = NavGetProcAddress(ProcessHandle, 
		(LPSTR)"NTDLL.DLL", (LPSTR)"RtlInitUnicodeString");
	LPVOID pLdrLoadDll = NavGetProcAddress(ProcessHandle,
		(LPSTR)"NTDLL.DLL", (LPSTR)"LdrLoadDll");

	LPCWSTR ModulePath = L"C:\\Users\\Murilo\\Desktop\\ZwQuerySystemInformation\\outros\\assembly\\dllexample_x64.dll";

	LPVOID source = VirtualAllocEx(ProcessHandle, NULL, 1024, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	SIZE_T writtenPath = 0;

	WriteProcessMemory(ProcessHandle, source, ModulePath,
		(wcsnlen_s(ModulePath, MAX_PATH) + 2) * sizeof(WCHAR), &writtenPath);

	LPVOID target = VirtualAllocEx(ProcessHandle, NULL, 128, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);	

	LPVOID dllHandle = VirtualAllocEx(ProcessHandle, NULL, sizeof(HANDLE), 
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	LPVOID bufferAddr = NULL;
	SIZE_T bufferSize = 0;

	NavAllocRemoteLoader(
		(DWORD64)pRtlInitUnicodeString, 
		(DWORD64)source, 
		(DWORD64)target,
		(DWORD64)pLdrLoadDll,
		(DWORD64)target,
		(DWORD64)dllHandle,
		*Rip, 
		&bufferAddr, &bufferSize);

	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeWrittenBytes = 0;

	NavWriteRemoteLoader(ProcessHandle, bufferAddr, bufferSize, &shellcodeAddr, &shellcodeWrittenBytes);

	*Rip = (DWORD64)shellcodeAddr;
}

VOID NAVAPI SwitchContextCallbackX86(LPVOID Context, HANDLE hThread, DWORD ProcessId, DWORD *Eip) {
	//*Eip = 0xffffffff;
}

int main(void) {
	//PNAV_THREAD_INFORMATION threads = NULL;
	//DWORD numOfThreads = 0;
	//NavEnumProcessThreads(TARGET_PROCESS, &threads, &numOfThreads);

	//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threads->ThreadId);

	//NavSwitchThreadContext(hThread, SwitchContextCallbackX64, SwitchContextCallbackX86);

	LoadLibraryW(L"C:\\Users\\Murilo\\Desktop\\ZwQuerySystemInformation\\outros\\assembly\\dllexample_x64.dll");

	getchar();
	return 0;
}