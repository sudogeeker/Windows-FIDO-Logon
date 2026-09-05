#pragma once

#include "CCredential.h"
#include "Configuration.h"
#include "Dll.h"
#include "helpers.h"

#include <credentialprovider.h>
#include <memory>

class CProvider : public ICredentialProvider
{
public:
	IFACEMETHODIMP_(ULONG) AddRef() noexcept override { return InterlockedIncrement(&_references); }
	IFACEMETHODIMP_(ULONG) Release() noexcept override
	{
		const LONG value = InterlockedDecrement(&_references);
		if (!value) delete this;
		return value;
	}
	IFACEMETHODIMP QueryInterface(REFIID riid, void** value) noexcept override
	{
		static const QITAB interfaces[] = { QITABENT(CProvider, ICredentialProvider), { 0 } };
		return QISearch(this, interfaces, riid, value);
	}

	IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario, DWORD flags) override;
	IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION*) override { return E_NOTIMPL; }
	IFACEMETHODIMP Advise(ICredentialProviderEvents* events, UINT_PTR context) override;
	IFACEMETHODIMP UnAdvise() override;
	IFACEMETHODIMP GetFieldDescriptorCount(DWORD* count) override;
	IFACEMETHODIMP GetFieldDescriptorAt(DWORD index, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** descriptor) override;
	IFACEMETHODIMP GetCredentialCount(DWORD* count, DWORD* defaultIndex, BOOL* autoLogon) override;
	IFACEMETHODIMP GetCredentialAt(DWORD index, ICredentialProviderCredential** credential) override;

	friend HRESULT CSample_CreateInstance(REFIID riid, void** value);

protected:
	CProvider();
	~CProvider();

private:
	LONG _references = 1;
	std::shared_ptr<Configuration> _configuration;
	CCredential* _credential = nullptr;
};
