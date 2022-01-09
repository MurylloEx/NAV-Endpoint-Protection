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


typedef NTSTATUS (NTAPI *PLdrLoadDll)(
	IN PWCHAR               PathToFile OPTIONAL, 
	IN ULONG                Flags OPTIONAL, 
	IN PUNICODE_STRING      ModuleFileName, 
	OUT PHANDLE             ModuleHandle); 

typedef VOID(__stdcall* PRtlInitUnicodeString)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString);

#define TARGET_PROCESS 16880


#pragma region "Remote Process DLL Injection Tests"

VOID NAVAPI SwitchContextCallbackX64(LPVOID Context, HANDLE hThread, DWORD ProcessId, DWORD64 *Rip) {
	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	
	LPVOID pRtlInitUnicodeString = NavGetProcAddress(ProcessHandle, (LPSTR)"NTDLL.DLL", (LPSTR)"RtlInitUnicodeString");
	LPVOID pLdrLoadDll = NavGetProcAddress(ProcessHandle, (LPSTR)"NTDLL.DLL", (LPSTR)"LdrLoadDll");

	LPCWSTR ModulePath = L"C:\\Users\\Muryllo\\Desktop\\assembly\\dllexample_x64.dll";
	SIZE_T ModulePathLen = (wcsnlen_s(ModulePath, MAX_PATH) + 1) * sizeof(WCHAR);

	LPVOID remoteDllPath = VirtualAllocEx(ProcessHandle, NULL, ModulePathLen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	SIZE_T writtenPath = 0;

	if (remoteDllPath == NULL) return;

	LPVOID nullBlock = malloc(ModulePathLen);

	if (nullBlock == NULL) return;

	ZeroMemory(nullBlock, ModulePathLen);

	WriteProcessMemory(ProcessHandle, remoteDllPath, nullBlock, ModulePathLen, &writtenPath); //Zerar a memória remota
	WriteProcessMemory(ProcessHandle, remoteDllPath, ModulePath, ModulePathLen, &writtenPath); //Escrever o caminho da DLL

	LPVOID remoteDllHandle = VirtualAllocEx(ProcessHandle, NULL, sizeof(HANDLE), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //DLL Handle
	LPVOID remoteUnicodeString = VirtualAllocEx(ProcessHandle, NULL, 12, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); //Estrutura Unicode String

	LPVOID bufferAddr = NULL;
	SIZE_T bufferSize = 0;

	//Constrói o Payload para ser escrito no processo alvo
	NavAllocRemoteLoaderX64(
		(DWORD64)pRtlInitUnicodeString, 
		(DWORD64)remoteDllPath,
		(DWORD64)remoteUnicodeString,
		(DWORD64)pLdrLoadDll,
		(DWORD64)remoteUnicodeString,
		(DWORD64)remoteDllHandle,
		*Rip, 
		&bufferAddr, &bufferSize);

	LPVOID shellcodeAddr = NULL;
	SIZE_T shellcodeWrittenBytes = 0;

	NavWriteRemoteLoader(ProcessHandle, bufferAddr, bufferSize, &shellcodeAddr, &shellcodeWrittenBytes); //Aloca e escreve o Loader no processo

	*Rip = (DWORD64)shellcodeAddr;
}

VOID NAVAPI SwitchContextCallbackX86(LPVOID Context, HANDLE hThread, DWORD ProcessId, DWORD *Eip) {
	//*Eip = 0xffffffff;
}

#pragma endregion


VOID SomeThread(LPVOID Params) {
	UNREFERENCED_PARAMETER(Params);
	DWORD Count = 0;
	while (true) {
		Count = Count + 1 % 4096;
		if (Count == 4095)
			Sleep(3000);
	}
}


NTSTATUS NTAPI LdrLoadDll(
	IN PWCHAR PathToFile, 
	IN ULONG Flags, 
	IN PUNICODE_STRING ModuleFileName, 
	OUT PHANDLE ModuleHandle)
{
	PLdrLoadDll pLdrLoadDll = (PLdrLoadDll)NavGetProcAddress(
		GetCurrentProcess(), (LPSTR)"NTDLL.DLL", (LPSTR)"LdrLoadDll");

	HANDLE dllHandle = NULL;

	return pLdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
}


VOID RemoteInjection(VOID) {
	PNAV_THREAD_INFORMATION threads = NULL;
	DWORD numOfThreads = 0;
	NavEnumProcessThreads(TARGET_PROCESS, &threads, &numOfThreads);

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threads->ThreadId);
	NavSwitchThreadContext(hThread, SwitchContextCallbackX64, SwitchContextCallbackX86);
}

VOID SelfInjection(VOID) {
	DWORD ThreadId = 0;
	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)SomeThread, NULL, NULL, &ThreadId);

	Sleep(3000);

	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadId);

	NavSwitchThreadContext(hThread, SwitchContextCallbackX64, SwitchContextCallbackX86);
}

VOID LoadTestDll(VOID) {
	UNICODE_STRING unicodestring;
	HANDLE dllHandle = NULL;

	RtlInitUnicodeString(&unicodestring, L"C:\\Users\\Muryllo\\Desktop\\assembly\\dllexample_x64.dll");

	LdrLoadDll(NULL, 0, &unicodestring, &dllHandle);
}


int main(void) {

	//RemoteInjection();
	SelfInjection();
	//LoadTestDll();

	getchar();
	return 0;
}

