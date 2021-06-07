#ifndef UNICODE
#define UNICODE
#endif

#include <vld.h>

#include <stdio.h>

#include "nav/base/network.h"

int main(void)
{
	NAV_TCP_INFO tcpInfo = { 0 };

	NavRetrieveTcpTable(&tcpInfo);

	for (DWORD k = 0; k < tcpInfo.TcpTablev4->dwNumEntries; k++) {
		MIB_TCPROW_OWNER_PID row = tcpInfo.TcpTablev4->table[k];
		printf("IPv4 PID: %d | Remote Port: %d | Local Port: %d | TCP State: %d\n", 
			row.dwOwningPid,
			ntohs((u_short)row.dwRemotePort),
			ntohs((u_short)row.dwLocalPort),
			row.dwState);
	}

	for (DWORD k = 0; k < tcpInfo.TcpTablev6->dwNumEntries; k++) {
		MIB_TCP6ROW_OWNER_PID row = tcpInfo.TcpTablev6->table[k];
		printf("IPv6 PID: %d | Remote Port: %d | Local Port: %d | TCP State: %d\n",
			row.dwOwningPid,
			ntohs((u_short)row.dwRemotePort),
			ntohs((u_short)row.dwLocalPort),
			row.dwState);
	}

	NavReleaseTcpTable(&tcpInfo);

	getchar();
	return 0;
}
