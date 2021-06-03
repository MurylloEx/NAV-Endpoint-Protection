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
		this->m_pCallbacks[ulCallbackType] = pCallback;
		return TRUE;
	}
	return FALSE;
}

BOOL CNavWmiEventSink::UnregisterCallback(
	/* [in] */ ULONG ulCallbackType)
{
	if ((ulCallbackType > 0) && (ulCallbackType < 7)) {
		this->m_pCallbacks[ulCallbackType] = NULL;
		return TRUE;
	}
	return FALSE;	
}

VOID CNavWmiEventSink::SetParameters(
	/* [in] */ PVOID pData)
{
	this->m_Parameters = pData;
}

PVOID CNavWmiEventSink::GetParameters()
{
	return this->m_Parameters;
}

VOID CNavWmiEventSink::SetFlags(
	/* [in] */ ULONG64 flags)
{
	this->m_Flags = flags;
}

ULONG64 CNavWmiEventSink::GetFlags()
{
	return this->m_Flags;
}


BOOL NAVAPI NavWmiCoInitializeEx() 
{
	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiCoInitializeSecurity() 
{
	HRESULT Status = CoInitializeSecurity(
		NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(Status) && (Status != RPC_E_TOO_LATE))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiCoCreateInstance(
	IWbemLocator** ppLocator) 
{
	if (FAILED(CoCreateInstance(
		CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
		IID_IWbemLocator, (LPVOID*)ppLocator)))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiCoConnectServer(
	IWbemLocator* pLocator, 
	IWbemServices** ppSvc)
{
	if (FAILED(pLocator->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), NULL, NULL,
		NULL, NULL, NULL, NULL, ppSvc)))
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

BOOL NAVAPI NavWmiCoCreateUnsecuredApartment(
	IUnsecuredApartment** ppUnsecApp, 
	CNavWmiEventSink* pSink, 
	IUnknown** ppStubUnk, 
	IWbemObjectSink** ppStubSink)
{
	if (FAILED(CoCreateInstance(CLSID_UnsecuredApartment, NULL,
		CLSCTX_LOCAL_SERVER, IID_IUnsecuredApartment, (void**)ppUnsecApp)))
		return FALSE;
	pSink->AddRef();
	(*ppUnsecApp)->CreateObjectStub(pSink, ppStubUnk);
	(*ppStubUnk)->QueryInterface(IID_IWbemObjectSink, (void**)ppStubSink);
	return TRUE;
}

BOOL NAVAPI NavWmiCoExecNotificationQueryAsync(
	IWbemServices* pSvc, 
	IWbemObjectSink* pStubSink, 
	const OLECHAR* strQueryLang, 
	const OLECHAR* strQuery)
{
	BSTR pszQueryLang = SysAllocString(strQueryLang);
	BSTR pszQuery = SysAllocString(strQuery);

	HRESULT status = pSvc->ExecNotificationQueryAsync(
		pszQueryLang, pszQuery, WBEM_FLAG_SEND_STATUS, NULL, pStubSink);

	SysFreeString(pszQueryLang);
	SysFreeString(pszQuery);

	if (FAILED(status))
		return FALSE;
	return TRUE;
}

BOOL NAVAPI NavWmiCoReadPropertyByName(
	const OLECHAR* pszPropName, 
	VARIANT* pValue, 
	IWbemClassObject* wbemObj, 
	CIMTYPE* pValueType)
{
	BSTR propName = SysAllocString(pszPropName);
	HRESULT status = wbemObj->Get(propName, NULL, pValue, pValueType, NULL);

	SysFreeString(propName);

	if (FAILED(status))
		return FALSE;
	return TRUE;
}

VOID NAVAPI NavWmiCoUninitialize()
{
	CoUninitialize();
}

BOOL NAVAPI NavWmiCoCancelNotificationQueryAsync(
	IWbemServices* pSvc,
	IWbemObjectSink* pStubSink)
{
	if (FAILED(pSvc->CancelAsyncCall(pStubSink)))
		return FALSE;
	return TRUE;
}