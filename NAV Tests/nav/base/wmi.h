#pragma once

#define _WIN32_DCOM

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include "status.h"

#pragma comment(lib, "wbemuuid.lib")


#define NAV_WMI_CALLBACK_ADD_REFERENCE		0UL
#define NAV_WMI_CALLBACK_RELEASE			1UL
#define NAV_WMI_CALLBACK_QUERY_INTERFACE	2UL
#define NAV_WMI_CALLBACK_INDICATE			3UL
#define NAV_WMI_CALLBACK_SET_EVENT			4UL
#define NAV_WMI_CALLBACK_STATUS_COMPLETE	5UL
#define NAV_WMI_CALLBACK_STATUS_PROGRESS	6UL


class CNavWmiEventSink : public IWbemObjectSink
{
	LONG m_lRef = 0;
	PVOID m_pCallbacks[7] = { 0 }; /* The value is 7 because we can assume
									7 types of distincts callbacks. */
public:

	CNavWmiEventSink() {
		ZeroMemory(m_pCallbacks, sizeof(PVOID) * 7);
	}
	~CNavWmiEventSink() {
		ZeroMemory(m_pCallbacks, sizeof(PVOID) * 7);
	}

	virtual ULONG STDMETHODCALLTYPE AddRef();
	virtual ULONG STDMETHODCALLTYPE Release();
	virtual HRESULT STDMETHODCALLTYPE QueryInterface(
		/* [in] */ REFIID riid,
		/* [in] */ void** ppv);

	virtual HRESULT STDMETHODCALLTYPE Indicate(
		/* [in] */ LONG lObjectCount,
		/* [in] */ IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray);

	virtual HRESULT STDMETHODCALLTYPE SetStatus(
		/* [in] */ LONG lFlags,
		/* [in] */ HRESULT hResult,
		/* [in] */ BSTR strParam,
		/* [in] */ IWbemClassObject __RPC_FAR *pObjParam);

	BOOL STDMETHODCALLTYPE RegisterCallback(
		/* [in] */ ULONG ulCallbackType,
		/* [in] */ PVOID pCallback);

	BOOL STDMETHODCALLTYPE UnregisterCallback(
		/* [in] */ ULONG ulCallbackType);

};


typedef ULONG(STDMETHODCALLTYPE *LPNavWmiAddReferenceCallback)(
	/* [in] */ const CNavWmiEventSink* pCNavEvSink);
typedef ULONG(STDMETHODCALLTYPE *LPNavWmiReleaseCallback)(
	/* [in] */ const CNavWmiEventSink* pCNavEvSink);
typedef HRESULT(STDMETHODCALLTYPE *LPNavWmiQueryInterfaceCallback)(
	/* [in] */ const CNavWmiEventSink* pCNavEvSink,
	/* [in] */ REFIID riid,
	/* [in] */ void** ppv);
typedef HRESULT(STDMETHODCALLTYPE *LPNavWmiIndicateCallback)(
	/* [in] */ const CNavWmiEventSink* pCNavEvSink,
	/* [in] */ LONG lObjectCount,
	/* [in] */ IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray);
typedef HRESULT(STDMETHODCALLTYPE *LPNavWmiSetEventCallback)(
	/* [in] */ const CNavWmiEventSink* pCNavEvSink,
	/* [in] */ LONG lFlags,
	/* [in] */ HRESULT hResult,
	/* [in] */ BSTR strParam,
	/* [in] */ IWbemClassObject __RPC_FAR *pObjParam);
typedef VOID(STDMETHODCALLTYPE *LPNavWmiStatusCompleteCallback)(
	/* [in] */ const CNavWmiEventSink* pCNavEvSink,
	/* [in] */ HRESULT hResult);
typedef VOID(STDMETHODCALLTYPE *LPNavWmiStatusProgressCallback)(
	/* [in] */ const CNavWmiEventSink* pCNavEvSink);


BOOL NAVAPI NavWmiCoInitializeEx();
BOOL NAVAPI NavWmiCoInitializeSecurity();
BOOL NAVAPI NavWmiCoCreateInstance(
	/* [in] */ IWbemLocator* pLocator);
BOOL NAVAPI NavWmiConnectServer(
	/* [in] */ IWbemLocator* pLocator,
	/* [in] */ IWbemServices* pSvc);
BOOL NAVAPI NavWmiCoSetProxyBlanket(
	/* [in] */ IWbemServices* pSvc);
BOOL NAVAPI NavWmiExecNotificationQueryAsync(
	/* [in] */ IWbemServices* pSvc,
	/* [in] */ IWbemObjectSink* pStubSink,
	/* [in] */ const char* strQueryLang,
	/* [in] */ const char* strQuery);