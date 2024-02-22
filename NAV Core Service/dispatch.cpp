#include "pch.h"
#include "status.h"
#include "dispatch.h"

VOID WINAPI ServiceStart(PSERVICE_CONTEXT Context) {
    BeginStartService(Context);
    // TODO: work here.
    AdvanceStartCheckpoint(Context); //1st checkpoint
    // TODO: work here.
    AdvanceStartCheckpoint(Context); //2st checkpoint

    EndStartService(Context);
}

DWORD WINAPI ServicePause(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    BeginPauseService(Context);
    // TODO: work here.
    EndPauseService(Context);

    return NO_ERROR;
}

DWORD WINAPI ServiceContinue(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    BeginContinueService(Context);
    // TODO: work here.
    EndContinueService(Context);

    return NO_ERROR;
}

DWORD WINAPI ServiceStop(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    BeginStopService(Context);
    // TODO: work here.
    EndStopService(Context);

    return NO_ERROR;
}

DWORD WINAPI ServiceInterrogate(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    return NO_ERROR;
}

DWORD WINAPI ServiceDeviceEvent(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    return NO_ERROR;
}

DWORD WINAPI ServicePowerEvent(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    return NO_ERROR;
}

DWORD WINAPI ServicePreShutdown(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context) {
    return NO_ERROR;
}

