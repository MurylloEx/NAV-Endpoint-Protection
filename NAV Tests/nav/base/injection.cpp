#include "injection.h"

NAVSTATUS NAVAPI NavInjectLoadLibraryRoutine(
	IN DWORD ProcessId, 
	IN LPWSTR ModulePath,
	OUT HANDLE* ThreadHandle)
{
	SIZE_T ModulePathSize = (wcslen(ModulePath) + 1) * sizeof(wchar_t);
	HANDLE TargetProcess = OpenProcess(
		PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, ProcessId);

	if (TargetProcess == INVALID_HANDLE_VALUE) {
		return NAV_INJECT_LOAD_LIBRARY_ROUTINE_STATUS_FAILED;
	}
	
	PVOID ModulePathAddress = VirtualAllocEx(
		TargetProcess, NULL, ModulePathSize, MEM_COMMIT, PAGE_READWRITE);

	if (ModulePathAddress == NULL) {
		CloseHandle(TargetProcess);
		return NAV_INJECT_LOAD_LIBRARY_ROUTINE_STATUS_FAILED;
	}

	SIZE_T BytesWritten = 0;

	BOOL WriteStatus = WriteProcessMemory(
		TargetProcess, ModulePathAddress, 
		ModulePath, ModulePathSize, &BytesWritten);

	if (WriteStatus == FALSE) {
		CloseHandle(TargetProcess);
		return NAV_INJECT_LOAD_LIBRARY_ROUTINE_STATUS_FAILED;
	}

	HANDLE RemoteThread = CreateRemoteThread(TargetProcess, NULL, NULL, 
		(LPTHREAD_START_ROUTINE)LoadLibraryW, ModulePathAddress, NULL, NULL);

	*ThreadHandle = RemoteThread;

	return NAV_INJECT_LOAD_LIBRARY_ROUTINE_STATUS_SUCCESS;
}