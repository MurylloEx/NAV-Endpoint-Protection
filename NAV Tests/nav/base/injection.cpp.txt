#include "injection.h"
#include "memory.h"

#define MAXIMUM_SUPPORTED_EXTENSION     512
#define SIZE_OF_80387_REGISTERS      80

typedef struct _FLOATING_SAVE_AREA {
	DWORD   ControlWord;
	DWORD   StatusWord;
	DWORD   TagWord;
	DWORD   ErrorOffset;
	DWORD   ErrorSelector;
	DWORD   DataOffset;
	DWORD   DataSelector;
	BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
	DWORD   Spare0;
} FLOATING_SAVE_AREA;

typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct DECLSPEC_ALIGN(16) _CONTEXT64 {

	DWORD64 P1Home;
	DWORD64 P2Home;
	DWORD64 P3Home;
	DWORD64 P4Home;
	DWORD64 P5Home;
	DWORD64 P6Home;

	DWORD ContextFlags;
	DWORD MxCsr;

	WORD   SegCs;
	WORD   SegDs;
	WORD   SegEs;
	WORD   SegFs;
	WORD   SegGs;
	WORD   SegSs;
	DWORD EFlags;

	DWORD64 Dr0;
	DWORD64 Dr1;
	DWORD64 Dr2;
	DWORD64 Dr3;
	DWORD64 Dr6;
	DWORD64 Dr7;

	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;

	DWORD64 Rip;

	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	M128A VectorRegister[26];
	DWORD64 VectorControl;

	DWORD64 DebugControl;
	DWORD64 LastBranchToRip;
	DWORD64 LastBranchFromRip;
	DWORD64 LastExceptionToRip;
	DWORD64 LastExceptionFromRip;
} CONTEXT64, *PCONTEXT64;

typedef struct _CONTEXT32 {

	DWORD ContextFlags;

	DWORD   Dr0;
	DWORD   Dr1;
	DWORD   Dr2;
	DWORD   Dr3;
	DWORD   Dr6;
	DWORD   Dr7;

	FLOATING_SAVE_AREA FloatSave;

	DWORD   SegGs;
	DWORD   SegFs;
	DWORD   SegEs;
	DWORD   SegDs;

	DWORD   Edi;
	DWORD   Esi;
	DWORD   Ebx;
	DWORD   Edx;
	DWORD   Ecx;
	DWORD   Eax;

	DWORD   Ebp;
	DWORD   Eip;
	DWORD   SegCs;
	DWORD   EFlags;
	DWORD   Esp;
	DWORD   SegSs;

	BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];

} CONTEXT32, *PCONTEXT32;

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

NAVSTATUS NAVAPI NavEnumProcessThreads(
	IN DWORD ProcessId,
	OUT PNAV_THREAD_INFORMATION* ThreadInformation,
	OUT LPDWORD NumberOfThreads)
{
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (Snapshot == INVALID_HANDLE_VALUE)
		return NAV_ENUM_PROCESS_THREADS_STATUS_FAILED;

	*ThreadInformation = (PNAV_THREAD_INFORMATION)NavAllocMem(sizeof(NAV_THREAD_INFORMATION));
	*NumberOfThreads = 0;

	PNAV_THREAD_INFORMATION CurrentThread = *ThreadInformation;

	THREADENTRY32 ThreadEntry = { 0 };
	ThreadEntry.dwSize = sizeof(ThreadEntry);

	if (Thread32First(Snapshot, &ThreadEntry)) {
		do {
			if (ThreadEntry.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(ThreadEntry.th32OwnerProcessID)) {
				if (ThreadEntry.th32OwnerProcessID == ProcessId) {
					if (*NumberOfThreads == 0) {
						CurrentThread->ProcessId = ThreadEntry.th32OwnerProcessID;
						CurrentThread->ThreadId = ThreadEntry.th32ThreadID;
					}
					else {
						PNAV_THREAD_INFORMATION NextThread =
							(PNAV_THREAD_INFORMATION)NavAllocMem(sizeof(NAV_THREAD_INFORMATION));

						NextThread->ProcessId = ThreadEntry.th32OwnerProcessID;
						NextThread->ThreadId = ThreadEntry.th32ThreadID;

						CurrentThread->NextOffset = (LPVOID)NextThread;
						CurrentThread = NextThread;
					}
					*NumberOfThreads++;
				}
			}
		} while (Thread32Next(Snapshot, &ThreadEntry));
	}
	CloseHandle(Snapshot);

	return NAV_ENUM_PROCESS_THREADS_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavWriteInstruction(
	IN HANDLE ProcessHandle,
	IN BYTE* PageAddress,
	IN BYTE* InstructionBuffer,
	IN SIZE_T InstructionBufferSize,
	OUT SIZE_T* NumberOfBytesWritten)
{
	if (WriteProcessMemory(ProcessHandle, PageAddress, (LPCVOID)InstructionBuffer,
		InstructionBufferSize, NumberOfBytesWritten) == FALSE)
	{
		VirtualFreeEx(ProcessHandle, PageAddress, NULL, MEM_RELEASE);
		return NAV_WRITE_INSTRUCTION_STATUS_FAILED;
	}
	return NAV_WRITE_INSTRUCTION_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavAllocInstruction(
	IN HANDLE ProcessHandle,
	IN SIZE_T InstructionBufferSize,
	OUT BYTE** RemoteBuffer)
{
	BYTE* PageAddress = (BYTE*)VirtualAllocEx(ProcessHandle, NULL, InstructionBufferSize,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (PageAddress == NULL)
		return NAV_ALLOC_INSTRUCTION_STATUS_FAILED;

	*RemoteBuffer = PageAddress;

	return NAV_ALLOC_INSTRUCTION_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavTransferExecution(
	IN PNAV_TRANSFER_EXECUTION_CALLBACK Callback,
	IN PNAV_EXECUTION_ARGUMENTS Arguments,
	IN DWORD ThreadId,
	IN DWORD Architecture)
{
	HANDLE ThreadHandle = OpenThread(
		THREAD_SET_CONTEXT |
		THREAD_SUSPEND_RESUME |
		THREAD_GET_CONTEXT, FALSE, ThreadId);

	if (ThreadHandle == INVALID_HANDLE_VALUE)
		return NAV_TRANSFER_EXECUTION_OPEN_STATUS_FAILED;

	if (SuspendThread(ThreadHandle) == (DWORD)-1) {
		CloseHandle(ThreadHandle);
		return NAV_TRANSFER_EXECUTION_SUSPEND_STATUS_FAILED;
	}

	if (Architecture == NAVX86) {
		CONTEXT32 ThreadContext32 = { 0 };
		ThreadContext32.ContextFlags = CONTEXT_FULL;

		if (GetThreadContext(ThreadHandle, (LPCONTEXT)&ThreadContext32) == FALSE) {
			ResumeThread(ThreadHandle);
			CloseHandle(ThreadHandle);
			return NAV_TRANSFER_EXECUTION_GET_CONTEXT_STATUS_FAILED;
		}

		NAVSTATUS Status = NULL;
		ULONG_PTR InstructionPointer = (ULONG_PTR)ThreadContext32.Eip;
		Callback((ULONG_PTR)ThreadContext32.Eip, &InstructionPointer, Arguments, &Status);
		
		if (!NAV_SUCCESS(Status)) {
			CloseHandle(ThreadHandle);
			return NAV_TRANSFER_EXECUTION_SET_CONTEXT_STATUS_FAILED;
		}
		
		ThreadContext32.Eip = (DWORD)InstructionPointer;

		if (SetThreadContext(ThreadHandle, (LPCONTEXT)&ThreadContext32) == FALSE) {
			ResumeThread(ThreadHandle);
			CloseHandle(ThreadHandle);
			return NAV_TRANSFER_EXECUTION_SET_CONTEXT_STATUS_FAILED;
		}

	} else
	if (Architecture == NAVX64) {
		CONTEXT64 ThreadContext64 = { 0 };
		ThreadContext64.ContextFlags = CONTEXT_FULL;

		if (GetThreadContext(ThreadHandle, (LPCONTEXT)&ThreadContext64) == FALSE) {
			ResumeThread(ThreadHandle);
			CloseHandle(ThreadHandle);
			return NAV_TRANSFER_EXECUTION_GET_CONTEXT_STATUS_FAILED;
		}

		NAVSTATUS Status = NULL;
		ULONG_PTR InstructionPointer = (ULONG_PTR)ThreadContext64.Rip;
		Callback((ULONG_PTR)ThreadContext64.Rip, &InstructionPointer, Arguments, &Status);

		if (!NAV_SUCCESS(Status)) {
			CloseHandle(ThreadHandle);
			return NAV_TRANSFER_EXECUTION_SET_CONTEXT_STATUS_FAILED;
		}

		ThreadContext64.Rip = (DWORD64)InstructionPointer;

		if (SetThreadContext(ThreadHandle, (LPCONTEXT)&ThreadContext64) == FALSE) {
			ResumeThread(ThreadHandle);
			CloseHandle(ThreadHandle);
			return NAV_TRANSFER_EXECUTION_SET_CONTEXT_STATUS_FAILED;
		}

	}
	else {
		return NAV_TRANSFER_EXECUTION_STATUS_UNSUPPORTED_ARCH;
	}
	
	if (ResumeThread(ThreadHandle) == (DWORD)-1) {
		CloseHandle(ThreadHandle);
		return NAV_TRANSFER_EXECUTION_RESUME_STATUS_FAILED;
	}

	CloseHandle(ThreadHandle);
	return NAV_TRANSFER_EXECUTION_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavReleaseEnumProcessThreads(
	IN PNAV_THREAD_INFORMATION ThreadInformation, 
	IN DWORD NumberOfThreads)
{
	PNAV_THREAD_INFORMATION NextThread = ThreadInformation;
	for (DWORD ThreadOffset = 0; (ThreadOffset < NumberOfThreads) || (NumberOfThreads == NULL); ThreadOffset++) {
		if (NextThread == NULL) {
			break;
		}
		if (NextThread->NextOffset == NULL) {
			NavFreeMem(NextThread);
			break;
		}
		LPVOID NextOffset = NextThread->NextOffset;
		NavFreeMem(NextThread);
		NextThread = (PNAV_THREAD_INFORMATION)NextOffset;
	}
	return NAV_RELEASE_PROCESS_ENUM_THREADS_STATUS_SUCCESS;
}

VOID NAVAPI NavpTransferExecutionCallback(
	IN ULONG_PTR InstructionPointer, 
	OUT ULONG_PTR* NewInstructionPointer, 
	IN LPVOID Arguments, 
	OUT NAVSTATUS* Status)
{
	PNAV_EXECUTION_ARGUMENTS ExecutionArguments = (PNAV_EXECUTION_ARGUMENTS)Arguments;

	BYTE NavLoader32[] = {
		0x83, 0xEC, 0x28, 0x60, 0x9C, 0xB8, 0xFF, 0xFF,
		0xFF, 0xFF, 0x68, 0xDD, 0xDD, 0xDD, 0xDD, 0xFF,
		0xD0, 0x9D, 0x61, 0x83, 0xC4, 0x28, 0x68, 0xCC,
		0xCC, 0xCC, 0xCC, 0xC3
	};

	BYTE NavLoader64[] = {
		0x48, 0x83, 0xec, 0x28, 0x48, 0x89, 0x44, 0x24,
		0x18, 0x48, 0x89, 0x4c, 0x24, 0x10, 0x48, 0xb9,
		0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0x48, 0xb8, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,
		0xdd, 0xdd, 0xff, 0xd0, 0x48, 0x8b, 0x4c, 0x24,
		0x10, 0x48, 0x8b, 0x44, 0x24, 0x18, 0x48, 0x83,
		0xc4, 0x28, 0x49, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc,
		0xcc, 0xcc, 0xcc, 0xcc, 0x41, 0xff, 0xe3
	};

	if (ExecutionArguments->Architecture == NAVX86) {
		*(DWORD*)((DWORD)NavLoader32 + 6)  = (DWORD)ExecutionArguments->LoaderAddress;
		*(DWORD*)((DWORD)NavLoader32 + 11) = (DWORD)ExecutionArguments->ModulePathAddress;
		*(DWORD*)((DWORD)NavLoader32 + 23) = (DWORD)InstructionPointer;
		ExecutionArguments->InstructionBuffer = NavLoader32;
		ExecutionArguments->InstructionBufferSize = sizeof(NavLoader32);
	} else 
	if (ExecutionArguments->Architecture == NAVX64) {
		*(DWORD64*)((DWORD64)NavLoader64 + 0x1a) = (DWORD64)ExecutionArguments->LoaderAddress;
		*(DWORD64*)((DWORD64)NavLoader64 + 0x10) = (DWORD64)ExecutionArguments->ModulePathAddress;
		*(DWORD64*)((DWORD64)NavLoader64 + 0x34) = (DWORD64)InstructionPointer;
		ExecutionArguments->InstructionBuffer = NavLoader64;
		ExecutionArguments->InstructionBufferSize = sizeof(NavLoader64);
	}

	*Status = NavAllocInstruction(
		ExecutionArguments->ProcessHandle,
		ExecutionArguments->InstructionBufferSize,
		&ExecutionArguments->RemoteInstructionBuffer);

	if (!NAV_SUCCESS(*Status)) {
		return;
	}

	SIZE_T InstructionWrittenBytes = 0;

	*Status = NavWriteInstruction(
		ExecutionArguments->ProcessHandle, 
		ExecutionArguments->RemoteInstructionBuffer,
		ExecutionArguments->InstructionBuffer, 
		ExecutionArguments->InstructionBufferSize, 
		&InstructionWrittenBytes);

	if (!NAV_SUCCESS(*Status)) {
		return;
	}

	*NewInstructionPointer = (ULONG_PTR)ExecutionArguments->RemoteInstructionBuffer;
}

NAVSTATUS NAVAPI NavExecuteRemoteInstruction(
	IN DWORD ProcessId,
	IN LPCWSTR ModulePath,
	IN LPVOID LoaderAddress,
	IN DWORD Architecture)
{
	NAVSTATUS Status;
	DWORD NumberOfThreads = 0;
	PNAV_THREAD_INFORMATION ThreadInformation = NULL;

	Status = NavEnumProcessThreads(ProcessId, &ThreadInformation, &NumberOfThreads);
	if (!NAV_SUCCESS(Status)) {
		return FALSE;
	}

	HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
	if (ProcessHandle == NULL) {
		return FALSE;
	}

	SIZE_T ModulePathWrittenBytes = 0;
	SIZE_T ModulePathSize = (wcslen(ModulePath) + 1) * sizeof(WCHAR);
	LPVOID ModulePathAddress = VirtualAllocEx(ProcessHandle, NULL, ModulePathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (ModulePathAddress == NULL) {
		return FALSE;
	}

	if (WriteProcessMemory(
			ProcessHandle, 
			ModulePathAddress, 
			ModulePath, 
			ModulePathSize, 
			&ModulePathWrittenBytes) == FALSE) 
	{
		return FALSE;
	}

	DWORD ThreadId = NULL;
	NAV_EXECUTION_ARGUMENTS Arguments = { 0 };

	Arguments.ProcessHandle = ProcessHandle;
	Arguments.Architecture = Architecture;
	Arguments.LoaderAddress = LoaderAddress;
	Arguments.ModulePathAddress = ModulePathAddress;

	/* Selecionar a thread do processo. */

	Status = NavTransferExecution(NavpTransferExecutionCallback, &Arguments, ThreadInformation->ThreadId, Architecture);
	if (!NAV_SUCCESS(Status)) {
		return FALSE;
	}

	Status = NavReleaseEnumProcessThreads(ThreadInformation, NumberOfThreads);
	if (!NAV_SUCCESS(Status)) {
		return FALSE;
	}

	return TRUE;
}