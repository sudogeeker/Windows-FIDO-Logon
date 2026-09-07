#include "CProvider.h"

#include "Logger.h"
#include "scenario.h"
#include "Localization.h"

#include <set>
#include <new>



CProvider::CProvider() : _configuration(std::make_shared<Configuration>())
{
	_configuration->Load();
	DllAddRef();
}

CProvider::~CProvider()
{
	UnAdvise();
	ClearCredentials();
	DllRelease();
}

HRESULT CProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags)
{
	ClearCredentials();
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
	for (auto& credential : _credentials) credential->FullReset();
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
	const HRESULT status = FieldDescriptorCoAllocCopy(s_rgScenarioCredProvFieldDescriptors[index], descriptor);
	if (FAILED(status)) return status;
	const PCWSTR localizedLabel = UiFieldLabel(static_cast<FIELD_ID>(index));
	if (localizedLabel && *localizedLabel)
	{
		CoTaskMemFree((*descriptor)->pszLabel);
		(*descriptor)->pszLabel = nullptr;
		const HRESULT labelStatus = SHStrDupW(localizedLabel, &(*descriptor)->pszLabel);
		if (FAILED(labelStatus))
		{
			CoTaskMemFree(*descriptor);
			*descriptor = nullptr;
			return labelStatus;
		}
	}
	return S_OK;
}

void CProvider::ClearCredentials()
{
	// LogonUI may still hold references to the old enumeration.
	for (auto& credential : _credentials) credential->Retire();
	_credentials.clear();
	_credentialsReady = false;
}

HRESULT CProvider::SetUserArray(ICredentialProviderUserArray* users)
{
	ClearCredentials();
	_users = users;
	return S_OK;
}

HRESULT CProvider::CreateCredentials()
{
	if (_credentialsReady) return S_OK;
	if (_configuration->isRemoteSession ||
		(_configuration->provider.scenario != CPUS_LOGON &&
		 _configuration->provider.scenario != CPUS_UNLOCK_WORKSTATION)) return E_NOTIMPL;
	if (!_users) return S_OK;
	try
	{
		// Commit only a complete enumeration. Never publish a partial user list.
		std::vector<Microsoft::WRL::ComPtr<CCredential>> credentials;
		auto append = [&](PCWSTR username, PCWSTR computer, PCWSTR sid) -> HRESULT
		{
			Microsoft::WRL::ComPtr<CCredential> credential;
			credential.Attach(new CCredential(_configuration));
			const HRESULT status = credential->Initialize(s_rgScenarioCredProvFieldDescriptors,
				s_rgScenarioUsernamePassword, username, computer, nullptr, sid);
			if (FAILED(status)) return status;
			credentials.push_back(std::move(credential));
			return S_OK;
		};
		DWORD count = 0;
		HRESULT status = _users->GetCount(&count);
		if (FAILED(status)) return status;
		std::set<std::wstring> seen;
		for (DWORD index = 0; index < count; ++index)
		{
			Microsoft::WRL::ComPtr<ICredentialProviderUser> user;
			status = _users->GetAt(index, &user);
			if (FAILED(status)) return status;
			if (!user) return E_UNEXPECTED;
			GUID providerId{};
			status = user->GetProviderID(&providerId);
			if (FAILED(status)) return status;
			if (providerId != Identity_LocalUserProvider) continue;
			PWSTR rawSid = nullptr;
			status = user->GetSid(&rawSid);
			std::unique_ptr<wchar_t, decltype(&CoTaskMemFree)> sid(rawSid, CoTaskMemFree);
			if (FAILED(status)) return status;
			if (!sid || !*sid) continue;
			std::wstring username, computer;
			if (!localfido::ResolveLocalSid(sid.get(), username, computer)) continue;
			if (!seen.insert(sid.get()).second) continue;
			status = append(username.c_str(), computer.c_str(), sid.get());
			if (FAILED(status)) return status;
		}
		CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS options = CPAO_NONE;
		status = _users->GetAccountOptions(&options);
		if (FAILED(status)) return status;
		if (options & CPAO_EMPTY_LOCAL)
		{
			status = append(nullptr, nullptr, nullptr);
			if (FAILED(status)) return status;
		}
		_credentials = std::move(credentials);
		_credentialsReady = true;
		return S_OK;
	}
	catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
}

HRESULT CProvider::GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon)
{
	if (!count || !defaultIndex || !autoLogon) return E_INVALIDARG;
	*count = 0;
	*defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
	*autoLogon = FALSE;
	const HRESULT status = CreateCredentials();
	if (FAILED(status)) return status;
	*count = static_cast<DWORD>(_credentials.size());
	return S_OK;
}

HRESULT CProvider::GetCredentialAt(DWORD index, ICredentialProviderCredential** credential)
{
	if (!credential) return E_INVALIDARG;
	*credential = nullptr;
	const HRESULT status = CreateCredentials();
	if (FAILED(status)) return status;
	if (index >= _credentials.size()) return E_INVALIDARG;
	return _credentials[index]->QueryInterface(IID_ICredentialProviderCredential,
		reinterpret_cast<void**>(credential));
}

HRESULT CSample_CreateInstance(REFIID riid, void** value)
{
	if (!value) return E_INVALIDARG;
	*value = nullptr;
	try
	{
		auto provider = new CProvider();
		const HRESULT status = provider->QueryInterface(riid, value);
		provider->Release();
		return status;
	}
	catch (const std::bad_alloc&) { return E_OUTOFMEMORY; }
}
