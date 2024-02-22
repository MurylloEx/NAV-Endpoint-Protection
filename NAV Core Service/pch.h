#ifndef PCH_H
#define PCH_H

// adicione os cabeçalhos que você deseja pré-compilar aqui

#include <Windows.h>
#include <Dbt.h>

#pragma pack(push, 4)

typedef struct _SERVICE_CHECKPOINT {
    BYTE StartCheckpoint;
    BYTE PauseCheckpoint;
    BYTE ContinueCheckpoint;
    BYTE StopCheckpoint;
} SERVICE_CHECKPOINT, * PSERVICE_CHECKPOINT;

#pragma pack(pop)

typedef struct _SERVICE_CONTEXT {
    LPWSTR* Arguments;
    DWORD NumberOfArguments;
    SERVICE_STATUS ServiceStatus;
    SERVICE_STATUS_HANDLE ServiceStatusHandle;
    PSERVICE_CHECKPOINT ServiceCheckpoint;
    HDEVNOTIFY DeviceNotificationHandle;
    HPOWERNOTIFY PowerAcDcNotificationHandle;
    HPOWERNOTIFY PowerBatteryNotificationHandle;
    PVOID ServiceControlDispatchTable[16];
} SERVICE_CONTEXT, * PSERVICE_CONTEXT;

typedef DWORD(WINAPI* PSERVICE_CONTROL_DISPATCHER)(DWORD EventType, LPVOID EventData, PSERVICE_CONTEXT Context);


#endif //PCH_H
