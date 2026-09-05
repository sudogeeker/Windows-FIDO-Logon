#pragma once

#include "BrokerClient.h"
#include "Configuration.h"
#include "Dll.h"
#include "FIDODevice.h"
#include "helpers.h"
#include "scenario.h"

#include <credentialprovider.h>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class CCredential : public IConnectableCredentialProviderCredential
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
		static const QITAB interfaces[] = {
			QITABENT(CCredential, ICredentialProviderCredential),
			QITABENT(CCredential, IConnectableCredentialProviderCredential),
			{ 0 }
		};
		return QISearch(this, interfaces, riid, value);
	}

	IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* events) override;
	IFACEMETHODIMP UnAdvise() override;
	IFACEMETHODIMP SetSelected(BOOL* autoLogon) override;
	IFACEMETHODIMP SetDeselected() override;
	IFACEMETHODIMP GetFieldState(DWORD field, CREDENTIAL_PROVIDER_FIELD_STATE* state,
		CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive) override;
	IFACEMETHODIMP GetStringValue(DWORD field, PWSTR* value) override;
	IFACEMETHODIMP GetBitmapValue(DWORD field, HBITMAP* bitmap) override;
	IFACEMETHODIMP GetCheckboxValue(DWORD, BOOL*, PWSTR*) override { return E_NOTIMPL; }
	IFACEMETHODIMP GetComboBoxValueCount(DWORD field, DWORD* count, DWORD* selected) override;
	IFACEMETHODIMP GetComboBoxValueAt(DWORD field, DWORD item, PWSTR* value) override;
	IFACEMETHODIMP GetSubmitButtonValue(DWORD field, DWORD* adjacentTo) override;
	IFACEMETHODIMP SetStringValue(DWORD field, PCWSTR value) override;
	IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL) override { return E_NOTIMPL; }
	IFACEMETHODIMP SetComboBoxSelectedValue(DWORD field, DWORD selected) override;
	IFACEMETHODIMP CommandLinkClicked(DWORD) override { return E_NOTIMPL; }
	IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, PWSTR* statusText,
		CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
	IFACEMETHODIMP ReportResult(NTSTATUS status, NTSTATUS substatus, PWSTR* statusText,
		CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon) override;
	IFACEMETHODIMP Connect(IQueryContinueWithStatus* query) override;
	IFACEMETHODIMP Disconnect() override { return S_OK; }

	explicit CCredential(std::shared_ptr<Configuration> configuration);
	~CCredential();
	HRESULT Initialize(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptors,
		const FIELD_STATE_PAIR* states, PWSTR username, PWSTR domain, PWSTR password);
	HRESULT FullReset();

private:
	HRESULT SetMode(Mode mode);
	void SetStatus(const std::wstring& text, IQueryContinueWithStatus* query = nullptr);
	void ResetMfa();
	HRESULT PackLogon(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization);
	HRESULT PackPasswordChange(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization);
	static HRESULT ReplaceFieldString(PWSTR& destination, PCWSTR source);

	LONG _references = 1;
	std::shared_ptr<Configuration> _configuration;
	CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR _descriptors[FID_NUM_FIELDS]{};
	FIELD_STATE_PAIR _states[FID_NUM_FIELDS]{};
	PWSTR _strings[FID_NUM_FIELDS]{};
	ICredentialProviderCredentialEvents* _events = nullptr;
	localfido::BrokerClient _broker;
	std::optional<localfido::AuthenticationChallenge> _challenge;
	std::vector<FIDODevice> _devices;
	DWORD _selectedDevice = 0;
	std::wstring _sid;
	bool _mfaComplete = false;
	bool _passwordChangeAuthorized = false;
};
