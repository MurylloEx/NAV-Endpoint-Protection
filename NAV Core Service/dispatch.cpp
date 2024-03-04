#include "pch.h"
#include "status.h"
#include "dispatch.h"

VOID WINAPI ServiceStart(PSERVICE_CONTEXT Context) {
    BeginStartService(Context);
    // TODO: work here.
    OutputDebugStringW(L"Service is being started!");
    AdvanceStartCheckpoint(Context); //1st checkpoint
    
    EndStartService(Context);
}

DWORD WINAPI ServicePause(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    BeginPauseService(Context);
    // TODO: work here.
    OutputDebugStringW(L"Service is being paused!");
    EndPauseService(Context);

    return NO_ERROR;
}

DWORD WINAPI ServiceContinue(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    BeginContinueService(Context);
    // TODO: work here.
    OutputDebugStringW(L"Service is being resumed!");
    EndContinueService(Context);

    return NO_ERROR;
}

DWORD WINAPI ServiceStop(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    BeginStopService(Context);
    // TODO: work here.
    OutputDebugStringW(L"Service is being stopped!");
    EndStopService(Context);

    return NO_ERROR;
}

DWORD WINAPI ServiceInterrogate(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    OutputDebugStringW(L"Service is being interrogated!");
    return NO_ERROR;
}

DWORD WINAPI ServiceDeviceEvent(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    OutputDebugStringW(L"Received Service Device Event!");
    return NO_ERROR;
}

DWORD WINAPI ServicePowerEvent(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    OutputDebugStringW(L"Received Service Power Event!");

    return NO_ERROR;
}

DWORD WINAPI ServicePreShutdown(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    OutputDebugStringW(L"Received Service Pre-Shutdown Event!");
  
    return NO_ERROR;
}

