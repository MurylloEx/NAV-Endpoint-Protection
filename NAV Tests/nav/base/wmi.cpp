#include "wmi.h"

ULONG CNavWmiEventSink::AddRef()
{
	if (m_pCallbacks[NAV_WMI_CALLBACK_RELEASE] != NULL)
		return ((LPNavWmiReleaseCallback)m_pCallbacks[NAV_WMI_CALLBACK_RELEASE])(this);

	return InterlockedIncrement(&m_lRef);
}

ULONG CNavWmiEventSink::Release()
{
	if (m_pCallbacks[NAV_WMI_CALLBACK_RELEASE] != NULL)
		return ((LPNavWmiReleaseCallback)m_pCallbacks[NAV_WMI_CALLBACK_RELEASE])(this);

	LONG lRef = InterlockedDecrement(&m_lRef);
	if (lRef == 0)
		delete this;

	return lRef;
}

HRESULT CNavWmiEventSink::QueryInterface(
	/* [in] */ REFIID riid,
	/* [in] */ void** ppv)
{
	if ((riid == IID_IUnknown) || (riid == IID_IWbemObjectSink)){
		*ppv = (IWbemObjectSink*)this;
		AddRef();

		if (m_pCallbacks[NAV_WMI_CALLBACK_QUERY_INTERFACE] != NULL)
			return ((LPNavWmiQueryInterfaceCallback)m_pCallbacks[NAV_WMI_CALLBACK_QUERY_INTERFACE])(this, riid, ppv);

		return WBEM_S_NO_ERROR;
	}
	return E_NOINTERFACE;
}

HRESULT CNavWmiEventSink::Indicate(
	/* [in] */ LONG lObjectCount,
	/* [in] */ IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray) 
{
	if (m_pCallbacks[NAV_WMI_CALLBACK_INDICATE] != NULL)
		return ((LPNavWmiIndicateCallback)m_pCallbacks[NAV_WMI_CALLBACK_INDICATE])(this, lObjectCount, apObjArray);

	return WBEM_S_NO_ERROR;
}

HRESULT CNavWmiEventSink::SetStatus(
	/* [in] */ LONG lFlags,
	/* [in] */ HRESULT hResult,
	/* [in] */ BSTR strParam,
	/* [in] */ IWbemClassObject __RPC_FAR *pObjParam)
{
	if (lFlags == WBEM_STATUS_COMPLETE) {
		if (m_pCallbacks[NAV_WMI_CALLBACK_STATUS_COMPLETE] != NULL)
			((LPNavWmiStatusCompleteCallback)m_pCallbacks[NAV_WMI_CALLBACK_STATUS_COMPLETE])(this, hResult);
	}
	else if (lFlags == WBEM_STATUS_PROGRESS) {
		if (m_pCallbacks[NAV_WMI_CALLBACK_STATUS_PROGRESS] != NULL)
			((LPNavWmiStatusProgressCallback)m_pCallbacks[NAV_WMI_CALLBACK_STATUS_PROGRESS])(this);
	}

	if (m_pCallbacks[NAV_WMI_CALLBACK_SET_EVENT] != NULL)
		return ((LPNavWmiSetEventCallback)m_pCallbacks[NAV_WMI_CALLBACK_SET_EVENT])(
			this, lFlags, hResult, strParam, pObjParam);

	return WBEM_S_NO_ERROR;
}

BOOL CNavWmiEventSink::RegisterCallback(
	/* [in] */ ULONG ulCallbackType,
	/* [in] */ PVOID pCallback)
{
	if ((ulCallbackType > 0) && (ulCallbackType < 7)) {
		m_pCallbacks[ulCallbackType] = pCallback;
		return TRUE;
	}
	return FALSE;
}

BOOL CNavWmiEventSink::UnregisterCallback(
	/* [in] */ ULONG ulCallbackType)
{
	if ((ulCallbackType > 0) && (ulCallbackType < 7)) {
		m_pCallbacks[ulCallbackType] = NULL;
		return TRUE;
	}
	return FALSE;	
}

BOOL NAVAPI NavWmiCoInitializeEx() 
{
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiCoInitializeSecurity() 
{
	if (FAILED(CoInitializeSecurity(
		NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiCoCreateInstance(
	IWbemLocator* pLocator) 
{
	if (FAILED(CoCreateInstance(
		CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)&pLocator)))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiConnectServer(
	IWbemLocator* pLocator, 
	IWbemServices* pSvc)
{
	if (FAILED(pLocator->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), NULL, NULL,
		NULL, NULL, NULL, NULL, &pSvc)))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiCoSetProxyBlanket(
	IWbemServices* pSvc)
{
	if (FAILED(CoSetProxyBlanket(
		pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, 
		RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE)))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiExecNotificationQueryAsync(
	IWbemServices* pSvc, 
	IWbemObjectSink* pStubSink, 
	const char* strQueryLang, 
	const char* strQuery)
{
	if (FAILED(pSvc->ExecNotificationQueryAsync(
		_bstr_t(strQueryLang), _bstr_t(strQuery), WBEM_FLAG_SEND_STATUS, NULL, pStubSink)))
		return FALSE;
	return TRUE;
}