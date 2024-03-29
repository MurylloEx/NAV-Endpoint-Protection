#include "pch.h"
#include "status.h"
#include "system.h"
#include "dispatch.h"
#include "bootstrap.h"

#define SERVICE_NAME L"XxMySample"

DWORD WINAPI ServiceController(DWORD dwCtrlCode, DWORD dwEventType, LPVOID lpEventData, LPVOID lpContext) {
    if ((dwCtrlCode < SERVICE_CONTROL_STOP) || (dwCtrlCode > SERVICE_CONTROL_PRESHUTDOWN)) {
        return NO_ERROR;
    }

    PSERVICE_CONTEXT Context = (PSERVICE_CONTEXT)lpContext;
    PSERVICE_CONTROL_DISPATCHER Dispatcher = (PSERVICE_CONTROL_DISPATCHER)Context->ServiceControlDispatchTable[dwCtrlCode];

    return Dispatcher(dwEventType, lpEventData, Context);
}

PSERVICE_CONTEXT WINAPI CreateServiceContext(DWORD dwNumServicesArgs, LPWSTR* lpServiceArgVectors) {
    PSERVICE_CONTEXT Context = (PSERVICE_CONTEXT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SERVICE_CONTEXT));

    if (!Context) {
        return NULL;
    }

    Context->Arguments = lpServiceArgVectors;
    Context->NumberOfArguments = dwNumServicesArgs;
    Context->ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    Context->ServiceCheckpoint = (PSERVICE_CHECKPOINT)(&Context->ServiceStatus.dwCheckPoint);

    Context->ServiceControlDispatchTable[SERVICE_CONTROL_STOP]          = ServiceStop;
    Context->ServiceControlDispatchTable[SERVICE_CONTROL_PAUSE]         = ServicePause;
    Context->ServiceControlDispatchTable[SERVICE_CONTROL_CONTINUE]      = ServiceContinue;
    Context->ServiceControlDispatchTable[SERVICE_CONTROL_INTERROGATE]   = ServiceInterrogate;
    Context->ServiceControlDispatchTable[SERVICE_CONTROL_DEVICEEVENT]   = ServiceDeviceEvent;
    Context->ServiceControlDispatchTable[SERVICE_CONTROL_POWEREVENT]    = ServicePowerEvent;
    Context->ServiceControlDispatchTable[SERVICE_CONTROL_PRESHUTDOWN]   = ServicePreShutdown;

    Context->ServiceStatusHandle = RegisterServiceCtrlHandlerExW(SERVICE_NAME, ServiceController, (LPVOID)Context);

    if (!Context->ServiceStatusHandle) {
        HeapFree(GetProcessHeap(), NULL, Context);
        return NULL;
    }

    DEV_BROADCAST_DEVICEINTERFACE DeviceFilter = { 0 };

    DeviceFilter.dbcc_size = sizeof(DeviceFilter);
    DeviceFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    DeviceFilter.dbcc_classguid = GUID_DEVINTERFACE_VOLUME;

    Context->DeviceNotificationHandle = RegisterDeviceNotificationW(
        Context->ServiceStatusHandle, &DeviceFilter, DEVICE_NOTIFY_SERVICE_HANDLE);

    if (!Context->DeviceNotificationHandle) {
        HeapFree(GetProcessHeap(), NULL, Context);
        return NULL;
    }

    Context->PowerAcDcNotificationHandle = RegisterPowerSettingNotification(
        Context->ServiceStatusHandle, &GUID_ACDC_POWER_SOURCE, DEVICE_NOTIFY_SERVICE_HANDLE);

    if (!Context->PowerAcDcNotificationHandle) {
        UnregisterDeviceNotification(Context->DeviceNotificationHandle);
        HeapFree(GetProcessHeap(), NULL, Context);
        return NULL;
    }

    Context->PowerBatteryNotificationHandle = RegisterPowerSettingNotification(
        Context->ServiceStatusHandle, &GUID_BATTERY_PERCENTAGE_REMAINING, DEVICE_NOTIFY_SERVICE_HANDLE);

    if (!Context->PowerBatteryNotificationHandle) {
        UnregisterDeviceNotification(Context->DeviceNotificationHandle);
        UnregisterPowerSettingNotification(Context->PowerAcDcNotificationHandle);
        HeapFree(GetProcessHeap(), NULL, Context);
        return NULL;
    }

    return Context;
}

VOID WINAPI ServiceMain(DWORD dwNumServicesArgs, LPWSTR* lpServiceArgVectors) {
    PSERVICE_CONTEXT Context = CreateServiceContext(dwNumServicesArgs, lpServiceArgVectors);

    if (Context) {
        ServiceStart(Context);
    }
}

int main(int argc, wchar_t** argv) {
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    if (!IsRunningAsLocalSystem()) {
        return ERROR_INCOMPATIBLE_SERVICE_PRIVILEGE;
    }

    SERVICE_TABLE_ENTRYW ServiceTable[2] = { 0 };

    ServiceTable->lpServiceName = const_cast<LPWSTR>(SERVICE_NAME);
    ServiceTable->lpServiceProc = (LPSERVICE_MAIN_FUNCTIONW)ServiceMain;

    if (StartServiceCtrlDispatcherW(ServiceTable) == FALSE) {
        return GetLastError();
    }

    return EXIT_SUCCESS;
}
