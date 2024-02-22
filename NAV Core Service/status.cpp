#include "pch.h"
#include "status.h"

VOID BeginStartService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	Context->ServiceStatus.dwControlsAccepted = NULL;
	Context->ServiceStatus.dwWaitHint = 5000;
	Context->ServiceCheckpoint->StartCheckpoint = NULL;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID AdvanceStartCheckpoint(PSERVICE_CONTEXT Context) {
	Context->ServiceCheckpoint->StartCheckpoint++;
	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID EndStartService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	Context->ServiceStatus.dwWaitHint = NULL;
	Context->ServiceCheckpoint->StartCheckpoint = NULL;
	Context->ServiceStatus.dwControlsAccepted =
		SERVICE_ACCEPT_STOP |
		SERVICE_ACCEPT_PAUSE_CONTINUE |
		SERVICE_ACCEPT_POWEREVENT |
		SERVICE_ACCEPT_PRESHUTDOWN;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID BeginPauseService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_PAUSE_PENDING;
	Context->ServiceStatus.dwControlsAccepted = NULL;
	Context->ServiceStatus.dwWaitHint = 5000;
	Context->ServiceCheckpoint->PauseCheckpoint = NULL;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID AdvancePauseCheckpoint(PSERVICE_CONTEXT Context) {
	Context->ServiceCheckpoint->PauseCheckpoint++;
	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID EndPauseService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_PAUSED;
	Context->ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
	Context->ServiceStatus.dwWaitHint = NULL;
	Context->ServiceCheckpoint->PauseCheckpoint = NULL;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID BeginContinueService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_CONTINUE_PENDING;
	Context->ServiceStatus.dwControlsAccepted = NULL;
	Context->ServiceStatus.dwWaitHint = 5000;
	Context->ServiceCheckpoint->ContinueCheckpoint = NULL;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID AdvanceContinueCheckpoint(PSERVICE_CONTEXT Context) {
	Context->ServiceCheckpoint->ContinueCheckpoint++;
	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID EndContinueService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	Context->ServiceStatus.dwWaitHint = NULL;
	Context->ServiceCheckpoint->ContinueCheckpoint = NULL;
	Context->ServiceStatus.dwControlsAccepted =
		SERVICE_ACCEPT_STOP |
		SERVICE_ACCEPT_PAUSE_CONTINUE |
		SERVICE_ACCEPT_POWEREVENT |
		SERVICE_ACCEPT_PRESHUTDOWN;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID BeginStopService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
	Context->ServiceStatus.dwControlsAccepted = NULL;
	Context->ServiceStatus.dwWaitHint = 5000;
	Context->ServiceCheckpoint->StopCheckpoint = NULL;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID AdvanceStopCheckpoint(PSERVICE_CONTEXT Context) {
	Context->ServiceCheckpoint->StopCheckpoint++;
	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}

VOID EndStopService(PSERVICE_CONTEXT Context) {
	Context->ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	Context->ServiceStatus.dwControlsAccepted = NULL;
	Context->ServiceStatus.dwWaitHint = NULL;
	Context->ServiceCheckpoint->StopCheckpoint = NULL;

	SetServiceStatus(Context->ServiceStatusHandle, &Context->ServiceStatus);
}
