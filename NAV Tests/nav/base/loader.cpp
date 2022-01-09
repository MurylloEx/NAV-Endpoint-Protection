#include "loader.h"

NAVSTATUS NAVAPI NavInjectLoadLibraryRoutine(
	IN DWORD ProcessId,
	IN LPWSTR ModulePath,
	OUT HANDLE* ThreadHandle)
{
	SIZE_T ModulePathSize = (wcslen(ModulePath) + 1) * sizeof(WCHAR);
	HANDLE TargetProcess = OpenProcess(
		PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, ProcessId);

	if (TargetProcess == INVALID_HANDLE_VALUE) {
		return NAV_INJECT_LOAD_LIBRARY_ROUTINE_STATUS_FAILED;
	}

	PVOID ModulePathAddress = VirtualAllocEx(
		TargetProcess, NULL, ModulePathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

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

NAVSTATUS NAVAPI NavInjectGlobalModule(
	IN LPWSTR ModulePath,
	IN LPSTR Procedure,
	OUT HHOOK* HookHandle)
{
	HMODULE Module = LoadLibraryExW(ModulePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (Module == NULL) {
		return NAV_INJECT_GLOBAL_MODULE_STATUS_FAILED;
	}

	HOOKPROC ProcedureAddress = (HOOKPROC)GetProcAddress(Module, Procedure);
	if (ProcedureAddress == NULL) {
		return NAV_INJECT_GLOBAL_MODULE_STATUS_FAILED;
	}

	HHOOK Hook = SetWindowsHookW(WH_GETMESSAGE, ProcedureAddress);
	if (Hook == NULL) {
		return NAV_INJECT_GLOBAL_MODULE_STATUS_FAILED;
	}

	*HookHandle = Hook;
	return NAV_INJECT_GLOBAL_MODULE_STATUS_SUCCESS;
}


#ifdef _WIN64

NAVSTATUS NAVAPI NavAllocRemoteLoaderX64(
	IN DWORD64 PRtlInitUnicodeString,
	IN DWORD64 PSourceString,
	IN DWORD64 PTargetUnicodeString,
	IN DWORD64 PLdrLoadDll,
	IN DWORD64 PModuleFileName,
	IN DWORD64 PModuleHandle,
	IN DWORD64 POriginalRip,
	OUT PVOID *BufferAddress,
	OUT SIZE_T *BufferSize)
{
	BYTE Shellcode[] = {
		//0x48, 0x83, 0xEC, 0x40, 0x50, 0x41, 0x50, 0x41,
		//0x51, 0x52, 0x51, 0x48, 0xB8, 0xCC, 0xCC, 0xCC,
		//0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0xBA, 0xCC,
		//0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48,
		//0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		//0xCC, 0xFF, 0xD0, 0x48, 0xB8, 0xCC, 0xCC, 0xCC,
		//0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x49, 0xB8, 0xCC,
		//0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x49,
		//0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		//0xCC, 0xBA, 0x00, 0x00, 0x00, 0x00, 0xB9, 0x00,
		//0x00, 0x00, 0x00, 0xFF, 0xD0, 0x59, 0x5A, 0x41,
		//0x59, 0x41, 0x58, 0x58, 0x48, 0x83, 0xC4, 0x40,
		//0x49, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		//0xCC, 0xCC, 0x41, 0xFF, 0xE3

		0x48, 0x83, 0xEC, 0x40, 0x50, 0x41, 0x50, 0x41,
		0x51, 0x52, 0x51, 0x48, 0xB8, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48, 0xBA, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x48,
		0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xFF, 0xD0, 0x48, 0xB8, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x49, 0xB9, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x49,
		0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0x48, 0x31, 0xD2, 0x48, 0x31, 0xC9, 0xFF,
		0xD0, 0x4D, 0x31, 0xC9, 0x4D, 0x31, 0xC0, 0x59,
		0x5A, 0x41, 0x59, 0x41, 0x58, 0x58, 0x48, 0x83,
		0xC4, 0x40, 0x49, 0xBB, 0xCC, 0xCC, 0xCC, 0xCC,
		0xCC, 0xCC, 0xCC, 0xCC, 0x41, 0xFF, 0xE3
	};

	*(DWORD64*)((DWORD64)Shellcode + 13) = (DWORD64)PRtlInitUnicodeString;
	*(DWORD64*)((DWORD64)Shellcode + 23) = (DWORD64)PSourceString;
	*(DWORD64*)((DWORD64)Shellcode + 33) = (DWORD64)PTargetUnicodeString;
	*(DWORD64*)((DWORD64)Shellcode + 45) = (DWORD64)PLdrLoadDll;
	*(DWORD64*)((DWORD64)Shellcode + 55) = (DWORD64)PModuleHandle;
	*(DWORD64*)((DWORD64)Shellcode + 65) = (DWORD64)PModuleFileName;
	*(DWORD64*)((DWORD64)Shellcode + 100) = (DWORD64)POriginalRip;

	*BufferAddress = NavAllocMem(sizeof(Shellcode));
	*BufferSize = sizeof(Shellcode);

	if (*BufferAddress == NULL)
		return FALSE;

	CopyMemory(*BufferAddress, Shellcode, sizeof(Shellcode));

	return TRUE;
}

NAVSTATUS NAVAPI NavSwitchThreadContextX64(
	IN HANDLE ThreadHandle,
	IN PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX64 CallbackX64,
	IN PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX32 CallbackX32)
{
	DWORD ProcessId = GetProcessIdOfThread(ThreadHandle);

	if (ProcessId == NULL)
		return FALSE;

	if (NavIsX64Process(ProcessId) == TRUE) {
		if (SuspendThread(ThreadHandle) == (DWORD)-1)
			return FALSE;

		CONTEXT ThreadContext = { 0 };
		ThreadContext.ContextFlags = CONTEXT_FULL;

		if (GetThreadContext(ThreadHandle, &ThreadContext) == FALSE)
			return FALSE;

		CallbackX64(&ThreadContext, ThreadHandle, ProcessId, &ThreadContext.Rip);

		if (SetThreadContext(ThreadHandle, &ThreadContext) == FALSE)
			return FALSE;

		if (ResumeThread(ThreadHandle) == NULL)
			return FALSE;
	}
	else {
		if (SuspendThread(ThreadHandle) == (DWORD)-1)
			return FALSE;

		WOW64_CONTEXT ThreadContext = { 0 };
		ThreadContext.ContextFlags = CONTEXT_FULL;

		if (Wow64GetThreadContext(ThreadHandle, &ThreadContext) == FALSE)
			return FALSE;

		CallbackX32(&ThreadContext, ThreadHandle, ProcessId, &ThreadContext.Eip);

		if (Wow64SetThreadContext(ThreadHandle, &ThreadContext) == FALSE)
			return FALSE;

		if (ResumeThread(ThreadHandle) == (DWORD)-1)
			return FALSE;
	}

	return TRUE;
}

#elif defined(_WIN32)

NAVSTATUS NAVAPI NavSwitchThreadContextX32(
	IN HANDLE ThreadHandle,
	IN PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX32 Callback)
{
	DWORD ProcessId = GetProcessIdOfThread(ThreadHandle);

	if (ProcessId == NULL)
		return FALSE;

	if (NavIsX86Process(ProcessId) == TRUE) {
		if (SuspendThread(ThreadHandle) == (DWORD)-1)
			return FALSE;

		CONTEXT ThreadContext = { 0 };
		ThreadContext.ContextFlags = CONTEXT_FULL;

		if (GetThreadContext(ThreadHandle, &ThreadContext) == FALSE)
			return FALSE;

		Callback(&ThreadContext, ThreadHandle, ProcessId, &ThreadContext.Eip);

		if (SetThreadContext(ThreadHandle, &ThreadContext) == FALSE)
			return FALSE;

		if (ResumeThread(ThreadHandle) == (DWORD)-1)
			return FALSE;
	}
	else {
		return FALSE;
	}

	return TRUE;
}

#endif

NAVSTATUS NAVAPI NavAllocRemoteLoaderX32(
	IN DWORD32 PRtlInitUnicodeString,
	IN DWORD32 PSourceString,
	IN DWORD32 PTargetUnicodeString,
	IN DWORD32 PLdrLoadDll,
	IN DWORD32 PModuleFileName,
	IN DWORD32 PModuleHandle,
	IN DWORD32 POriginalEip,
	OUT PVOID *BufferAddress,
	OUT SIZE_T *BufferSize)
{
	BYTE Shellcode[] = {
		0x83, 0xEC, 0x40, 0x60, 0x9C, 0x50, 0xB8, 0xCC,
		0xCC, 0xCC, 0xCC, 0x68, 0xCC, 0xCC, 0xCC, 0xCC,
		0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF, 0xD0, 0xB8,
		0xCC, 0xCC, 0xCC, 0xCC, 0x68, 0xCC, 0xCC, 0xCC,
		0xCC, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0x6A, 0x00,
		0x6A, 0x00, 0xFF, 0xD0, 0x58, 0x9D, 0x61, 0x83,
		0xC4, 0x40, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
	};

	*(DWORD32*)((ULONG_PTR)Shellcode + 7) = (DWORD32)PRtlInitUnicodeString;
	*(DWORD32*)((ULONG_PTR)Shellcode + 12) = (DWORD32)PSourceString;
	*(DWORD32*)((ULONG_PTR)Shellcode + 17) = (DWORD32)PTargetUnicodeString;
	*(DWORD32*)((ULONG_PTR)Shellcode + 24) = (DWORD32)PLdrLoadDll;
	*(DWORD32*)((ULONG_PTR)Shellcode + 29) = (DWORD32)PModuleHandle;
	*(DWORD32*)((ULONG_PTR)Shellcode + 34) = (DWORD32)PModuleFileName;
	*(DWORD32*)((ULONG_PTR)Shellcode + 51) = (DWORD32)POriginalEip;

	*BufferAddress = NavAllocMem(sizeof(Shellcode));

	if (*BufferAddress == NULL)
		return FALSE;

	CopyMemory(*BufferAddress, Shellcode, sizeof(Shellcode));

	return TRUE;
}


NAVSTATUS NAVAPI NavGetModuleExportDirectory(
	IN HANDLE ProcessHandle,
	IN HMODULE ModuleHandle,
	OUT PIMAGE_EXPORT_DIRECTORY ExportDirectory,
	IN IMAGE_DOS_HEADER DosHeader,
	IN IMAGE_NT_HEADERS NtHeaders)
{
	BYTE* AllocatedPEHeader = (BYTE*)NavAllocMem(1000 * sizeof(UCHAR));
	PIMAGE_SECTION_HEADER ImageSectionHeaderAddress;
	DWORD EATAddress;

	if (!ExportDirectory)
		return FALSE;

	ZeroMemory(ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY));

	if (!ReadProcessMemory(ProcessHandle, (LPVOID)ModuleHandle, AllocatedPEHeader, (SIZE_T)1000, NULL))
		return FALSE;

	ImageSectionHeaderAddress = (PIMAGE_SECTION_HEADER)(AllocatedPEHeader + DosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (WORD i = 0; i < NtHeaders.FileHeader.NumberOfSections; i++, ImageSectionHeaderAddress++) {
		if (!ImageSectionHeaderAddress)
			continue;

		if (_stricmp((CHAR*)ImageSectionHeaderAddress->Name, ".edata") == 0) {
			if (!ReadProcessMemory(ProcessHandle, (LPVOID)(DWORD_PTR)ImageSectionHeaderAddress->VirtualAddress, ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL))
				continue;

			NavFreeMem(AllocatedPEHeader);
			return TRUE;
		}
	}

	EATAddress = NtHeaders.OptionalHeader.DataDirectory[0].VirtualAddress;
	if (!EATAddress)
		return FALSE;

	if (!ReadProcessMemory(ProcessHandle, (LPVOID)((DWORD_PTR)ModuleHandle + EATAddress), ExportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL))
		return FALSE;

	NavFreeMem(AllocatedPEHeader);
	return TRUE;
}

HMODULE NAVAPI NavGetModuleHandle(
	IN HANDLE ProcessHandle, 
	IN LPSTR ModuleName)
{
	MODULEENTRY32W ModuleEntry;
	HANDLE Toolhelp = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(ProcessHandle));
	CHAR ModuleChar[256] = { 0 };

	ModuleEntry.dwSize = sizeof(MODULEENTRY32W);
	Module32FirstW(Toolhelp, &ModuleEntry);
	do {
		size_t i;
		wcstombs_s(&i, ModuleChar, 256, ModuleEntry.szModule, 256);
		if (!_stricmp(ModuleChar, ModuleName))
		{
			CloseHandle(Toolhelp);
			return ModuleEntry.hModule;
		}
		ModuleEntry.dwSize = sizeof(MODULEENTRY32W);
	} while (Module32NextW(Toolhelp, &ModuleEntry));

	CloseHandle(Toolhelp);
	return NULL;
}

LPVOID NAVAPI NavGetProcAddress(
	IN HANDLE ProcessHandle, 
	IN LPSTR Module, 
	IN LPSTR FunctionName) 
{
	ULONG ProcessId = GetProcessId(ProcessHandle);
	HMODULE RemoteModuleHandle = NavGetModuleHandle(ProcessHandle, Module);
	IMAGE_DOS_HEADER DosHeader;
	IMAGE_NT_HEADERS NtHeaders;
	IMAGE_EXPORT_DIRECTORY EATDirectory;

	DWORD*   AddressOfFunctions;
	DWORD*   AddressOfNames;
	WORD*    AddressOfOrdinals;

	DWORD_PTR ExportBase;
	DWORD_PTR ExportSize;
	DWORD_PTR AddressOfFunction;
	DWORD_PTR AddressOfName;

	CHAR ProcedureName[256] = { 0 };
	CHAR RedirectName[256] = { 0 };
	CHAR ModuleName[256] = { 0 };
	CHAR RedirectedName[256] = { 0 };
	CHAR RedirectedFunctionName[256] = { 0 };

	WORD OrdinalValue;

	DWORD_PTR AddressOfRedirectedFunction;
	DWORD_PTR AddressOfRedirectedName;

	int a = 0;
	int b = 0;

	if (!RemoteModuleHandle)
		return NULL;

	// Load DOS PE header
	if (!ReadProcessMemory(ProcessHandle, (LPVOID)RemoteModuleHandle, &DosHeader, sizeof(IMAGE_DOS_HEADER), NULL) || DosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// Load NT PE headers
	if (!ReadProcessMemory(ProcessHandle, (LPVOID)((DWORD_PTR)RemoteModuleHandle + DosHeader.e_lfanew), &NtHeaders, sizeof(IMAGE_NT_HEADERS), NULL) || NtHeaders.Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// Load image export directory
	if (!NavGetModuleExportDirectory(ProcessHandle, RemoteModuleHandle, &EATDirectory, DosHeader, NtHeaders))
		return NULL;

	// Allocate room for all the function information
	AddressOfFunctions = (DWORD*)NavAllocMem(EATDirectory.NumberOfFunctions * sizeof(DWORD));
	AddressOfNames = (DWORD*)NavAllocMem(EATDirectory.NumberOfNames * sizeof(DWORD));
	AddressOfOrdinals = (WORD*)NavAllocMem(EATDirectory.NumberOfNames * sizeof(WORD));

	// Read function address locations
	if (!ReadProcessMemory(ProcessHandle, (LPVOID)((DWORD_PTR)RemoteModuleHandle + (DWORD_PTR)EATDirectory.AddressOfFunctions), AddressOfFunctions, EATDirectory.NumberOfFunctions * sizeof(DWORD), NULL)) {
		NavFreeMem(AddressOfFunctions);
		NavFreeMem(AddressOfNames);
		NavFreeMem(AddressOfOrdinals);
		return NULL;
	}

	// Read function name locations
	if (!ReadProcessMemory(ProcessHandle, (LPVOID)((DWORD_PTR)RemoteModuleHandle + (DWORD_PTR)EATDirectory.AddressOfNames), AddressOfNames, EATDirectory.NumberOfNames * sizeof(DWORD), NULL)) {
		NavFreeMem(AddressOfFunctions);
		NavFreeMem(AddressOfNames);
		NavFreeMem(AddressOfOrdinals);
		return NULL;
	}

	// Read function name ordinal locations
	if (!ReadProcessMemory(ProcessHandle, (LPVOID)((DWORD_PTR)RemoteModuleHandle + (DWORD_PTR)EATDirectory.AddressOfNameOrdinals), AddressOfOrdinals, EATDirectory.NumberOfNames * sizeof(WORD), NULL)) {
		NavFreeMem(AddressOfFunctions);
		NavFreeMem(AddressOfNames);
		NavFreeMem(AddressOfOrdinals);
		return NULL;
	}

	ExportBase = ((DWORD_PTR)RemoteModuleHandle + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	ExportSize = (ExportBase + NtHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);

	// Check each name for a match
	for (UINT i = 0; i < EATDirectory.NumberOfNames; ++i) {
		AddressOfFunction = (DWORD_PTR)RemoteModuleHandle + AddressOfFunctions[i];
		AddressOfName = (DWORD_PTR)RemoteModuleHandle + AddressOfNames[i];

		ZeroMemory(&ProcedureName, 256);

		if (!ReadProcessMemory(ProcessHandle, (LPVOID)AddressOfName, ProcedureName, 256, NULL))
			continue;

		// Skip until we find the matching function name
		if (_stricmp(ProcedureName, FunctionName) != 0)
			continue;

		// Check if address of function is found in another module
		if (AddressOfFunction >= ExportBase && AddressOfFunction <= ExportSize) {
			ZeroMemory(&RedirectName, 256);

			if (!ReadProcessMemory(ProcessHandle, (LPVOID)AddressOfFunction, RedirectName, 256, NULL))
				continue;

			ZeroMemory(&ModuleName, 256);
			ZeroMemory(&RedirectedName, 256);

			a = 0;
			for (; RedirectName[a] != '.'; a++)
				ModuleName[a] = RedirectName[a];
			a++;
			ModuleName[a] = '\0';

			b = 0;
			for (; RedirectName[a] != '\0'; a++, b++)
				RedirectedName[b] = RedirectName[a];
			b++;
			RedirectedName[b] = '\0';

			strcat_s(ModuleName, 256, ".dll");

			NavFreeMem(AddressOfFunctions);
			NavFreeMem(AddressOfNames);
			NavFreeMem(AddressOfOrdinals);

			return NavGetProcAddress(ProcessHandle, ModuleName, RedirectedName);
		}

		OrdinalValue = AddressOfOrdinals[i];

		if (OrdinalValue >= EATDirectory.NumberOfNames) {
			return NULL;
		}

		// If ordinal doesn't match index retrieve correct address
		if (OrdinalValue != i) {
			AddressOfRedirectedFunction = ((DWORD_PTR)RemoteModuleHandle + (DWORD_PTR)AddressOfFunctions[OrdinalValue]);
			AddressOfRedirectedName = ((DWORD_PTR)RemoteModuleHandle + (DWORD_PTR)AddressOfNames[OrdinalValue]);

			ZeroMemory(&RedirectedFunctionName, 256);

			NavFreeMem(AddressOfFunctions);
			NavFreeMem(AddressOfNames);
			NavFreeMem(AddressOfOrdinals);

			if (!ReadProcessMemory(ProcessHandle, (LPVOID)AddressOfRedirectedName, RedirectedFunctionName, 256, NULL))
				return NULL;
			else
				return (LPVOID)AddressOfRedirectedFunction;
		}
		// Otherwise return the address
		else {
			NavFreeMem(AddressOfFunctions);
			NavFreeMem(AddressOfNames);
			NavFreeMem(AddressOfOrdinals);

			return (LPVOID)AddressOfFunction;
		}
	}

	NavFreeMem(AddressOfFunctions);
	NavFreeMem(AddressOfNames);
	NavFreeMem(AddressOfOrdinals);

	return NULL;
}

NAVSTATUS NAVAPI NavWriteRemoteLoader(
	IN HANDLE ProcessHandle,
	IN LPVOID BufferAddress,
	IN SIZE_T BufferSize,
	OUT LPVOID *BaseAddress,
	OUT SIZE_T *BufferBytesWritten)
{
	LPVOID RemoteAddress = VirtualAllocEx(ProcessHandle, NULL,
		BufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (RemoteAddress == NULL)
		return FALSE;

	BOOL Status = WriteProcessMemory(ProcessHandle, RemoteAddress,
		BufferAddress, BufferSize, BufferBytesWritten);

	if (Status == FALSE)
		goto CLEANUP;

	Status = FlushInstructionCache(ProcessHandle, RemoteAddress, BufferSize);

	if (Status != FALSE) {
		*BaseAddress = RemoteAddress;
		return TRUE;
	}

CLEANUP:
	VirtualFreeEx(ProcessHandle, RemoteAddress, NULL, MEM_RELEASE);
	return FALSE;
}
