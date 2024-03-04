#include "network.h"
#include "memory.h"

NAVSTATUS NAVAPI NavRetrieveTcpTable(PNAV_TCP_INFO TcpInfo)
{
	DWORD Status = NULL;
	PVOID TcpTableBuffer = NULL;
	DWORD TcpTableSize = sizeof(MIB_TCPTABLE_OWNER_PID);
	
	do {
		Status = GetExtendedTcpTable(
			TcpTableBuffer, &TcpTableSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, NULL);
		if (TcpTableBuffer == NULL) {
			TcpTableBuffer = NavAllocate(TcpTableSize);
		}
		else {
			TcpTableBuffer = NavReAllocMem(TcpTableBuffer, TcpTableSize);
		}
	} while (Status == ERROR_INSUFFICIENT_BUFFER);

	if (Status != NO_ERROR)
		return NAV_RETRIEVE_TCP_TABLE_STATUS_FAILED;
	TcpInfo->TcpTablev4 = (PMIB_TCPTABLE_OWNER_PID)TcpTableBuffer;

	Status = NULL;
	TcpTableBuffer = NULL;
	TcpTableSize = sizeof(MIB_TCP6TABLE_OWNER_PID);

	do {
		Status = GetExtendedTcpTable(
			TcpTableBuffer, &TcpTableSize, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, NULL);
		if (TcpTableBuffer == NULL) {
			TcpTableBuffer = NavAllocate(TcpTableSize);
		}
		else {
			TcpTableBuffer = NavReAllocMem(TcpTableBuffer, TcpTableSize);
		}
	} while (Status == ERROR_INSUFFICIENT_BUFFER);

	if (Status != NO_ERROR)
		return NAV_RETRIEVE_TCP_TABLE_STATUS_FAILED;
	TcpInfo->TcpTablev6 = (PMIB_TCP6TABLE_OWNER_PID)TcpTableBuffer;

	return NAV_RETRIEVE_TCP_TABLE_STATUS_SUCCESS;
}

NAVSTATUS NAVAPI NavReleaseTcpTable(PNAV_TCP_INFO TcpInfo) 
{
	if (NavFree(TcpInfo->TcpTablev4) == FALSE)
		return NAV_RELEASE_TCP_TABLE_STATUS_FAILED;
	if (NavFree(TcpInfo->TcpTablev6) == FALSE)
		return NAV_RELEASE_TCP_TABLE_STATUS_FAILED;
	return NAV_RELEASE_TCP_TABLE_STATUS_SUCCESS;
}

