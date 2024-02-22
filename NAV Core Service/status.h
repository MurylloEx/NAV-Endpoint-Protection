#pragma once

#include "pch.h"
#include "bootstrap.h"

VOID WINAPI BeginStartService(PSERVICE_CONTEXT Context);
VOID WINAPI AdvanceStartCheckpoint(PSERVICE_CONTEXT Context);
VOID WINAPI EndStartService(PSERVICE_CONTEXT Context);

VOID WINAPI BeginPauseService(PSERVICE_CONTEXT Context);
VOID WINAPI AdvancePauseCheckpoint(PSERVICE_CONTEXT Context);
VOID WINAPI EndPauseService(PSERVICE_CONTEXT Context);

VOID WINAPI BeginContinueService(PSERVICE_CONTEXT Context);
VOID WINAPI AdvanceContinueCheckpoint(PSERVICE_CONTEXT Context);
VOID WINAPI EndContinueService(PSERVICE_CONTEXT Context);

VOID WINAPI BeginStopService(PSERVICE_CONTEXT Context);
VOID WINAPI AdvanceStopCheckpoint(PSERVICE_CONTEXT Context);
VOID WINAPI EndStopService(PSERVICE_CONTEXT Context);

