/* Apache-2.0; derived from the original project filter. */
#include "CCredentialProviderFilter.h"
#include "guid.h"
#include "Logger.h"
#include "RegistryReader.h"

#include <new>
#include <unknwn.h>

HRESULT CSample_CreateInstance(__in REFIID riid, __deref_out void** ppv)
{
	if (!ppv) return E_INVALIDARG;
	*ppv = nullptr;
	auto provider = new (std::nothrow) CCredentialProviderFilter();
	if (!provider) return E_OUTOFMEMORY;
	const HRESULT result = provider->QueryInterface(riid, ppv);
	provider->Release();
	return result;
}

HRESULT CCredentialProviderFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD,
	GUID* providers, BOOL* allowed, DWORD count)
{
	if (!providers || !allowed) return E_INVALIDARG;
	// Never affect RDP/CredUI/change-password/PLAP. This product's enforcement scope is
	// local interactive logon and workstation unlock only.
	if ((scenario != CPUS_LOGON && scenario != CPUS_UNLOCK_WORKSTATION) || GetSystemMetrics(SM_REMOTESESSION)) return S_OK;
	RegistryReader registry(CONFIG_REGISTRY_PATH);
	_filterEnabled = registry.GetBool(L"enable_filter");
	Logger::Get().logDebug = registry.GetBool(L"debug_log");
	for (DWORD index = 0; index < count; ++index)
	{
		// Filter decisions are shared with other registered filters. Only add a
		// denial; never restore TRUE after another filter has denied a provider.
		const bool isOurProvider = IsEqualGUID(providers[index], CLSID_WINDOWS_FIDO_LOGON);
		if ((_filterEnabled && !isOurProvider) || (!_filterEnabled && isOurProvider))
			allowed[index] = FALSE;
	}
	return S_OK;
}

HRESULT CCredentialProviderFilter::UpdateRemoteCredential(
	const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*)
{
	return E_NOTIMPL;
}

CCredentialProviderFilter::CCredentialProviderFilter() : _cRef(1) { DllAddRef(); }
CCredentialProviderFilter::~CCredentialProviderFilter() { DllRelease(); }
