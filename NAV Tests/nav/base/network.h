#pragma once

//#include <iphlpapi.h>
#include "status.h"
#include <ws2tcpip.h>
#include "winapi.h"

typedef struct _NAV_TCP_INFO { 
	PMIB_TCPTABLE_OWNER_PID TcpTablev4;
	PMIB_TCP6TABLE_OWNER_PID TcpTablev6;
} NAV_TCP_INFO, *PNAV_TCP_INFO;


NAVSTATUS NAVAPI NavRetrieveTcpTable(PNAV_TCP_INFO TcpInfo);
NAVSTATUS NAVAPI NavReleaseTcpTable(PNAV_TCP_INFO TcpInfo);