#include "CProvider.h"

#include "Logger.h"
#include "scenario.h"

#include <WtsApi32.h>
#include <new>

#pragma comment(lib, "Wtsapi32.lib")

CProvider::CProvider() : _configuration(std::make_shared<Configuration>())
{
	DllAddRef();
	_configuration->Load();
}

CProvider::~CProvider()
{
	UnAdvise();
	if (_credential) { _credential->Release(); _credential = nullptr; }
	DllRelease();
}

HRESULT CProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags)
{
	_configuration->provider.scenario = scenario;
	_configuration->provider.flags = flags;
	if (_configuration->isRemoteSession) return E_NOTIMPL;
	return (scenario == CPUS_LOGON || scenario == CPUS_UNLOCK_WORKSTATION) ? S_OK : E_NOTIMPL;
}

HRESULT CProvider::Advise(ICredentialProviderEvents* events, UINT_PTR context)
{
	if (!events) return E_INVALIDARG;
	UnAdvise();
	_configuration->provider.events = events;
	_configuration->provider.context = context;
	events->AddRef();
	return S_OK;
}

HRESULT CProvider::UnAdvise()
{
	if (_configuration && _configuration->provider.events)
	{
		_configuration->provider.events->Release();
		_configuration->provider.events = nullptr;
		_configuration->provider.context = 0;
	}
	if (_credential) _credential->FullReset();
	return S_OK;
}

HRESULT CProvider::GetFieldDescriptorCount(DWORD* count)
{
	if (!count) return E_INVALIDARG;
	*count = FID_NUM_FIELDS;
	return S_OK;
}

HRESULT CProvider::GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor)
{
	if (!descriptor || index >= FID_NUM_FIELDS) return E_INVALIDARG;
	return FieldDescriptorCoAllocCopy(s_rgScenarioCredProvFieldDescriptors[index], descriptor);
}

HRESULT CProvider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon)
{
	if (!count || !defaultIndex || !autoLogon) return E_INVALIDARG;
	*count = 1;
	*defaultIndex = _configuration->noDefault ? CREDENTIAL_PROVIDER_NO_DEFAULT : 0;
	*autoLogon = FALSE;
	return S_OK;
}

HRESULT CProvider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential)
{
	if (!credential || index != 0) return E_INVALIDARG;
	if (!_credential)
	{
		PWSTR sessionUser = nullptr;
		PWSTR sessionDomain = nullptr;
		if (_configuration->provider.scenario == CPUS_UNLOCK_WORKSTATION)
		{
			DWORD size = 0;
			WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &sessionUser, &size);
			WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSDomainName, &sessionDomain, &size);
		}
		_credential = new (std::nothrow) CCredential(_configuration);
		if (!_credential)
		{
			if (sessionUser) WTSFreeMemory(sessionUser);
			if (sessionDomain) WTSFreeMemory(sessionDomain);
			return E_OUTOFMEMORY;
		}
		const HRESULT status = _credential->Initialize(s_rgScenarioCredProvFieldDescriptors,
			s_rgScenarioUsernamePassword, sessionUser, sessionDomain, nullptr);
		if (sessionUser) WTSFreeMemory(sessionUser);
		if (sessionDomain) WTSFreeMemory(sessionDomain);
		if (FAILED(status)) { _credential->Release(); _credential = nullptr; return status; }
	}
	return _credential->QueryInterface(IID_IConnectableCredentialProviderCredential, reinterpret_cast<void**>(credential));
}

HRESULT CSample_CreateInstance(REFIID riid, void** value)
{
	if (!value) return E_INVALIDARG;
	*value = nullptr;
	auto provider = new (std::nothrow) CProvider();
	if (!provider) return E_OUTOFMEMORY;
	const HRESULT status = provider->QueryInterface(riid, value);
	provider->Release();
	return status;
}
