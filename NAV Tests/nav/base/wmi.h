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
	ULONG64 m_Flags = 0;
	PVOID m_Parameters = NULL;
	LONG m_lRef = 0;
	PVOID *m_pCallbacks = NULL; 

public:

	CNavWmiEventSink() {
		this->m_pCallbacks = new PVOID[7]();
	}
	~CNavWmiEventSink() {
		delete[] this->m_pCallbacks;
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

	VOID STDMETHODCALLTYPE SetParameters(
		/* [in] */ PVOID pData);

	PVOID STDMETHODCALLTYPE GetParameters();

	VOID STDMETHODCALLTYPE SetFlags(
		/* [in] */ ULONG64 flags);

	ULONG64 STDMETHODCALLTYPE GetFlags();
};


typedef ULONG(STDMETHODCALLTYPE *LPNavWmiAddReferenceCallback)(
	/* [in] */ CNavWmiEventSink* pCNavEvSink);
typedef ULONG(STDMETHODCALLTYPE *LPNavWmiReleaseCallback)(
	/* [in] */ CNavWmiEventSink* pCNavEvSink);
typedef HRESULT(STDMETHODCALLTYPE *LPNavWmiQueryInterfaceCallback)(
	/* [in] */ CNavWmiEventSink* pCNavEvSink,
	/* [in] */ REFIID riid,
	/* [in] */ void** ppv);
typedef HRESULT(STDMETHODCALLTYPE *LPNavWmiIndicateCallback)(
	/* [in] */ CNavWmiEventSink* pCNavEvSink,
	/* [in] */ LONG lObjectCount,
	/* [in] */ IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray);
typedef HRESULT(STDMETHODCALLTYPE *LPNavWmiSetEventCallback)(
	/* [in] */ CNavWmiEventSink* pCNavEvSink,
	/* [in] */ LONG lFlags,
	/* [in] */ HRESULT hResult,
	/* [in] */ BSTR strParam,
	/* [in] */ IWbemClassObject __RPC_FAR *pObjParam);
typedef VOID(STDMETHODCALLTYPE *LPNavWmiStatusCompleteCallback)(
	/* [in] */ CNavWmiEventSink* pCNavEvSink,
	/* [in] */ HRESULT hResult);
typedef VOID(STDMETHODCALLTYPE *LPNavWmiStatusProgressCallback)(
	/* [in] */ CNavWmiEventSink* pCNavEvSink);


BOOL NAVAPI NavWmiCoInitializeEx();
BOOL NAVAPI NavWmiCoInitializeSecurity();
BOOL NAVAPI NavWmiCoCreateInstance(
	/* [out] */ IWbemLocator** ppLocator);
BOOL NAVAPI NavWmiCoConnectServer(
	/* [in] */ IWbemLocator* pLocator,
	/* [out] */ IWbemServices** ppSvc);
BOOL NAVAPI NavWmiCoSetProxyBlanket(
	/* [in] */ IWbemServices* pSvc);
BOOL NAVAPI NavWmiCoCreateUnsecuredApartment(
	/* [out] */ IUnsecuredApartment** ppUnsecApp,
	/* [in] */ CNavWmiEventSink* pSink,
	/* [out] */ IUnknown** ppStubUnk,
	/* [out] */ IWbemObjectSink** ppStubSink);
BOOL NAVAPI NavWmiCoExecNotificationQueryAsync(
	/* [in] */ IWbemServices* pSvc,
	/* [in] */ IWbemObjectSink* pStubSink,
	/* [in] */ const OLECHAR* strQueryLang,
	/* [in] */ const OLECHAR* strQuery);
BOOL NAVAPI NavWmiCoReadPropertyByName(
	/* [in] */ const OLECHAR* pszPropName,
	/* [in] */ VARIANT* pValue,
	/* [in] */ IWbemClassObject* wbemObj,
	/* [in] */ CIMTYPE* pValueType);
VOID NAVAPI NavWmiCoUninitialize();
BOOL NAVAPI NavWmiCoCancelNotificationQueryAsync(
	/* [in] */ IWbemServices* pSvc,
	/* [in] */ IWbemObjectSink* pStubSink);