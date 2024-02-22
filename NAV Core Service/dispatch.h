#pragma once

#include "pch.h"

VOID WINAPI ServiceStart(PSERVICE_CONTEXT Context);

DWORD WINAPI ServicePause(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);
DWORD WINAPI ServiceContinue(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);
DWORD WINAPI ServiceStop(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);
DWORD WINAPI ServiceInterrogate(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);
DWORD WINAPI ServiceDeviceEvent(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);
DWORD WINAPI ServicePowerEvent(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);
DWORD WINAPI ServicePreShutdown(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);
