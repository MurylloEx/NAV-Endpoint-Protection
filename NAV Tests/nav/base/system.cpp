#pragma once

#include "system.h"
#include "memory.h"

BOOL NAVAPI NavIsX64System() {
	UNREFERENCED_PARAMETER(GetSystemWow64DirectoryW(NULL, 0));
	if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavIsX86System() {
	if (NavIsX64System() == FALSE)
		return TRUE;
	return FALSE;
}

BOOL NAVAPI NavIsX86Process(DWORD ProcessId) {
	BOOL IsX86Process = FALSE;
	HANDLE ProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, ProcessId);
	if (IsWow64Process(ProcessHandle, &IsX86Process) == FALSE)
		IsX86Process = FALSE;
	if (ProcessHandle != NULL)
		CloseHandle(ProcessHandle);
	return IsX86Process;
}

BOOL NAVAPI NavIsX64Process(DWORD ProcessId) {
	if (NavIsX86Process(ProcessId) == FALSE)
		return TRUE;
	return FALSE;
}

NAVSTATUS NAVAPI NavEnumProcessThreads(
	IN DWORD ProcessId,
	OUT PNAV_THREAD_INFORMATION* ThreadInformation,
	OUT LPDWORD NumberOfThreads)
{
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (Snapshot == INVALID_HANDLE_VALUE)
		return NAV_ENUM_PROCESS_THREADS_STATUS_FAILED;

	*ThreadInformation = (PNAV_THREAD_INFORMATION)NavAllocate(sizeof(NAV_THREAD_INFORMATION));
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
							(PNAV_THREAD_INFORMATION)NavAllocate(sizeof(NAV_THREAD_INFORMATION));

						NextThread->ProcessId = ThreadEntry.th32OwnerProcessID;
						NextThread->ThreadId = ThreadEntry.th32ThreadID;

						CurrentThread->NextOffset = (LPVOID)NextThread;
						CurrentThread = NextThread;
					}
					(*NumberOfThreads)++;
				}
			}
		} while (Thread32Next(Snapshot, &ThreadEntry));
	}
	CloseHandle(Snapshot);

	return NAV_ENUM_PROCESS_THREADS_STATUS_SUCCESS;
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
			NavFree(NextThread);
			break;
		}
		LPVOID NextOffset = NextThread->NextOffset;
		NavFree(NextThread);
		NextThread = (PNAV_THREAD_INFORMATION)NextOffset;
	}
	return NAV_RELEASE_PROCESS_ENUM_THREADS_STATUS_SUCCESS;
}