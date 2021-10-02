#pragma once

#include "winapi.h"
#include "status.h"
#include "memory.h"
#include "system.h"

typedef VOID(NAVAPI *PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX64)(
	IN LPVOID ThreadContext,
	IN HANDLE ThreadHandle,
	IN DWORD ProcessId,
	OUT DWORD64 *Rip);

typedef VOID(NAVAPI *PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX32)(
	IN LPVOID ThreadContext,
	IN HANDLE ThreadHandle,
	IN DWORD ProcessId,
	OUT DWORD *Eip);

NAVSTATUS NAVAPI NavInjectLoadLibraryRoutine(
	IN DWORD ProcessId,
	IN LPWSTR ModulePath,
	OUT HANDLE* ThreadHandle);

NAVSTATUS NAVAPI NavInjectGlobalModule(
	IN LPWSTR ModulePath,
	IN LPSTR Procedure,
	OUT HHOOK* HookHandle);

#if defined(_WIN64)

NAVSTATUS NAVAPI NavAllocRemoteLoaderX64(
	IN DWORD64 PRtlInitUnicodeString,
	IN DWORD64 PSourceString,
	IN DWORD64 PTargetUnicodeString,
	IN DWORD64 PLdrLoadDll,
	IN DWORD64 PModuleFileName,
	IN DWORD64 PModuleHandle,
	IN DWORD64 POriginalRip,
	OUT PVOID *BufferAddress,
	OUT SIZE_T *BufferSize);

NAVSTATUS NAVAPI NavAllocRemoteLoaderX32(
	IN DWORD32 PRtlInitUnicodeString,
	IN DWORD32 PSourceString,
	IN DWORD32 PTargetUnicodeString,
	IN DWORD32 PLdrLoadDll,
	IN DWORD32 PModuleFileName,
	IN DWORD32 PModuleHandle,
	IN DWORD32 POriginalEip,
	OUT PVOID *BufferAddress,
	OUT SIZE_T *BufferSize);

NAVSTATUS NAVAPI NavSwitchThreadContextX64(
	IN HANDLE ThreadHandle,
	IN PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX64 CallbackX64,
	IN PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX32 CallbackX32);

#define NavSwitchThreadContext NavSwitchThreadContextX64
#define NavAllocRemoteLoader NavAllocRemoteLoaderX64
#define PNAV_SWITCH_THREAD_CONTEXT_CALLBACK PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX64;

#elif defined(_WIN32)

NAVSTATUS NAVAPI NavAllocRemoteLoaderX32(
	IN DWORD32 PRtlInitUnicodeString,
	IN DWORD32 PSourceString,
	IN DWORD32 PTargetUnicodeString,
	IN DWORD32 PLdrLoadDll,
	IN DWORD32 PModuleFileName,
	IN DWORD32 PModuleHandle,
	IN DWORD32 POriginalEip,
	OUT PVOID *BufferAddress,
	OUT SIZE_T *BufferSize);

NAVSTATUS NAVAPI NavSwitchThreadContextX32(
	IN HANDLE ThreadHandle,
	IN PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX32 Callback);

#define NavSwitchThreadContext NavSwitchThreadContextX32
#define NavAllocRemoteLoader NavAllocRemoteLoaderX32
#define PNAV_SWITCH_THREAD_CONTEXT_CALLBACK PNAV_SWITCH_THREAD_CONTEXT_CALLBACKX32;

#endif

NAVSTATUS NAVAPI NavGetModuleExportDirectory(
	IN HANDLE ProcessHandle,
	IN HMODULE ModuleHandle,
	OUT PIMAGE_EXPORT_DIRECTORY ExportDirectory,
	IN IMAGE_DOS_HEADER DosHeader,
	IN IMAGE_NT_HEADERS NtHeaders);

HMODULE NAVAPI NavGetModuleHandle(
	IN HANDLE ProcessHandle,
	IN LPSTR ModuleName);

LPVOID NAVAPI NavGetProcAddress(
	IN HANDLE ProcessHandle,
	IN LPSTR Module,
	IN LPSTR FunctionName);

NAVSTATUS NAVAPI NavWriteRemoteLoader(
	IN HANDLE ProcessHandle,
	IN LPVOID BufferAddress,
	IN SIZE_T BufferSize,
	OUT LPVOID *BaseAddress,
	OUT SIZE_T *BufferBytesWritten);
