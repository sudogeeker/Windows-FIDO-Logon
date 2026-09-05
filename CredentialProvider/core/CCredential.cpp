#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include "CCredential.h"

#include "Convert.h"
#include "LocalAccount.h"
#include "LocalCredentialStore.h"
#include "Logger.h"
#include "Mode.h"
#include "guid.h"
#include "resource.h"

#include <Windows.h>
#include <fido.h>
#include <new>

namespace
{
	void ClearPackedSerialization(CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization)
	{
		if (!serialization || !serialization->rgbSerialization) return;
		SecureZeroMemory(serialization->rgbSerialization, serialization->cbSerialization);
		CoTaskMemFree(serialization->rgbSerialization);
		serialization->rgbSerialization = nullptr;
		serialization->cbSerialization = 0;
	}
}

CCredential::CCredential(std::shared_ptr<Configuration> configuration) : _configuration(std::move(configuration))
{
	DllAddRef();
}

CCredential::~CCredential()
{
	UnAdvise();
	for (DWORD index = 0; index < FID_NUM_FIELDS; ++index)
	{
		if (_strings[index])
		{
			if (_descriptors[index].cpft == CPFT_PASSWORD_TEXT)
				SecureZeroMemory(_strings[index], (wcslen(_strings[index]) + 1) * sizeof(wchar_t));
			CoTaskMemFree(_strings[index]);
		}
		CoTaskMemFree(_descriptors[index].pszLabel);
	}
	DllRelease();
}

HRESULT CCredential::ReplaceFieldString(PWSTR& destination, PCWSTR source)
{
	PWSTR replacement = nullptr;
	const HRESULT status = SHStrDupW(source ? source : L"", &replacement);
	if (FAILED(status)) return status;
	if (destination)
	{
		SecureZeroMemory(destination, (wcslen(destination) + 1) * sizeof(wchar_t));
		CoTaskMemFree(destination);
	}
	destination = replacement;
	return S_OK;
}

HRESULT CCredential::Initialize(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptors,
	const FIELD_STATE_PAIR* states, PWSTR username, PWSTR domain, PWSTR password)
{
	if (!descriptors || !states) return E_INVALIDARG;
	for (DWORD index = 0; index < FID_NUM_FIELDS; ++index)
	{
		HRESULT status = FieldDescriptorCopy(descriptors[index], &_descriptors[index]);
		if (FAILED(status)) return status;
		_states[index] = states[index];
		status = ReplaceFieldString(_strings[index], L"");
		if (FAILED(status)) return status;
	}
	_configuration->credential.username = username ? username : L"";
	_configuration->credential.domain = domain ? domain : L"";
	_configuration->credential.password = password ? password : L"";
	ReplaceFieldString(_strings[FID_LARGE_TEXT], L"Windows FIDO Logon");
	ReplaceFieldString(_strings[FID_SMALL_TEXT], L"Enter a local account password.");
	ReplaceFieldString(_strings[FID_USERNAME], _configuration->credential.username.c_str());
	ReplaceFieldString(_strings[FID_PASSWORD], _configuration->credential.password.c_str());
	ReplaceFieldString(_strings[FID_SUBMIT_BUTTON], L"Sign in");
	return S_OK;
}

HRESULT CCredential::Advise(ICredentialProviderCredentialEvents* events)
{
	if (!events) return E_INVALIDARG;
	UnAdvise();
	_events = events;
	_events->AddRef();
	return S_OK;
}

HRESULT CCredential::UnAdvise()
{
	if (_events) { _events->Release(); _events = nullptr; }
	return S_OK;
}

HRESULT CCredential::SetSelected(BOOL* autoLogon)
{
	if (!autoLogon) return E_INVALIDARG;
	*autoLogon = FALSE;
	return S_OK;
}

HRESULT CCredential::SetDeselected()
{
	ResetMfa();
	return S_OK;
}

HRESULT CCredential::GetFieldState(DWORD field, CREDENTIAL_PROVIDER_FIELD_STATE* state,
	CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* interactive)
{
	if (field >= FID_NUM_FIELDS || !state || !interactive) return E_INVALIDARG;
	*state = _states[field].cpfs;
	*interactive = _states[field].cpfis;
	return S_OK;
}

HRESULT CCredential::GetStringValue(DWORD field, PWSTR* value)
{
	if (field >= FID_NUM_FIELDS || !value) return E_INVALIDARG;
	return SHStrDupW(_strings[field] ? _strings[field] : L"", value);
}

HRESULT CCredential::GetBitmapValue(DWORD field, HBITMAP* bitmap)
{
	if (field != FID_LOGO || !bitmap) return E_INVALIDARG;
	*bitmap = static_cast<HBITMAP>(LoadImageW(HINST_THISDLL, MAKEINTRESOURCEW(IDB_TILE_IMAGE), IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR));
	return *bitmap ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

HRESULT CCredential::GetComboBoxValueCount(DWORD field, DWORD* count, DWORD* selected)
{
	if (field != FID_DEVICE_SELECT || !count || !selected) return E_INVALIDARG;
	*count = static_cast<DWORD>(_devices.size());
	*selected = _selectedDevice < _devices.size() ? _selectedDevice : 0;
	return S_OK;
}

HRESULT CCredential::GetComboBoxValueAt(DWORD field, DWORD item, PWSTR* value)
{
	if (field != FID_DEVICE_SELECT || !value || item >= _devices.size()) return E_INVALIDARG;
	return SHStrDupW(Convert::ToWString(_devices[item].ToString()).c_str(), value);
}

HRESULT CCredential::GetSubmitButtonValue(DWORD field, DWORD* adjacentTo)
{
	if (field != FID_SUBMIT_BUTTON || !adjacentTo) return E_INVALIDARG;
	*adjacentTo = _configuration->mode == Mode::CHANGE_PASSWORD ? FID_NEW_PASS_2 :
		(_configuration->mode == Mode::FIDO ? FID_FIDO_PIN : FID_PASSWORD);
	return S_OK;
}

HRESULT CCredential::SetStringValue(DWORD field, PCWSTR value)
{
	if (field >= FID_NUM_FIELDS || !value) return E_INVALIDARG;
	std::wstring* target = nullptr;
	switch (field)
	{
	case FID_USERNAME: target = &_configuration->credential.username; break;
	case FID_PASSWORD: target = &_configuration->credential.password; break;
	case FID_FIDO_PIN: target = &_configuration->credential.fidoPin; break;
	case FID_NEW_PASS_1: target = &_configuration->credential.newPassword1; break;
	case FID_NEW_PASS_2: target = &_configuration->credential.newPassword2; break;
	default: return E_INVALIDARG;
	}
	if (_descriptors[field].cpft == CPFT_PASSWORD_TEXT && !target->empty())
		SecureZeroMemory(target->data(), target->size() * sizeof(wchar_t));
	*target = value;
	return ReplaceFieldString(_strings[field], value);
}

HRESULT CCredential::SetComboBoxSelectedValue(DWORD field, DWORD selected)
{
	if (field != FID_DEVICE_SELECT || selected >= _devices.size()) return E_INVALIDARG;
	_selectedDevice = selected;
	return S_OK;
}

void CCredential::SetStatus(const std::wstring& text, IQueryContinueWithStatus* query)
{
	ReplaceFieldString(_strings[FID_SMALL_TEXT], text.c_str());
	if (query) query->SetStatusMessage(text.c_str());
	if (_events) _events->SetFieldString(this, FID_SMALL_TEXT, text.c_str());
}

HRESULT CCredential::SetMode(Mode mode)
{
	_configuration->mode = mode;
	const FIELD_STATE_PAIR* requested = mode == Mode::FIDO ? s_rgScenarioFido :
		(mode == Mode::CHANGE_PASSWORD ? s_rgScenarioChangePassword : s_rgScenarioUsernamePassword);
	for (DWORD index = 0; index < FID_NUM_FIELDS; ++index)
	{
		_states[index] = requested[index];
		if (mode == Mode::FIDO && index == FID_DEVICE_SELECT && _devices.size() <= 1)
			_states[index] = { CPFS_HIDDEN, CPFIS_NONE };
		if (_events)
		{
			_events->SetFieldState(this, index, _states[index].cpfs);
			_events->SetFieldInteractiveState(this, index, _states[index].cpfis);
		}
	}
	return S_OK;
}

void CCredential::ResetMfa()
{
	_mfaComplete = false;
	_challenge.reset();
	_devices.clear();
	_selectedDevice = 0;
	if (!_configuration->credential.fidoPin.empty())
		SecureZeroMemory(_configuration->credential.fidoPin.data(), _configuration->credential.fidoPin.size() * sizeof(wchar_t));
	_configuration->credential.fidoPin.clear();
	ReplaceFieldString(_strings[FID_FIDO_PIN], L"");
}

HRESULT CCredential::Connect(IQueryContinueWithStatus* query)
{
	if (_configuration->mode == Mode::CHANGE_PASSWORD)
		return _passwordChangeAuthorized ? S_OK : E_ACCESSDENIED;
	if (_configuration->credential.username.empty() || _configuration->credential.password.empty())
	{
		SetStatus(L"A local username and Windows password are required.", query);
		return E_INVALIDARG;
	}

	if (!_challenge)
	{
		std::wstring username, computer, sid;
		DWORD accountError = ERROR_SUCCESS;
		if (!localfido::ResolveLocalAccount(_configuration->credential.username, username, computer, sid, &accountError))
		{
			SetStatus(L"Only local SAM accounts are supported.", query);
			return HRESULT_FROM_WIN32(accountError);
		}
		_configuration->credential.username = username;
		_configuration->credential.domain = computer;
		_sid = sid;
		localfido::AuthenticationChallenge challenge;
		std::wstring brokerError;
		if (!_broker.BeginAuthentication(sid, challenge, brokerError))
		{
			if (localfido::LocalCredentialStore::IsSidEnforced(sid))
			{
				SetStatus(L"MFA is enforced and the local Broker is unavailable. Sign-in is blocked.", query);
				return E_ACCESSDENIED;
			}
			_mfaComplete = true;
			return S_OK;
		}
		if (!challenge.enforced)
		{
			if (localfido::LocalCredentialStore::IsSidEnforced(sid))
			{
				SetStatus(L"MFA policy state is inconsistent. Sign-in is blocked.", query);
				return E_ACCESSDENIED;
			}
			_mfaComplete = true;
			return S_OK;
		}
		_challenge = std::move(challenge);
		_devices = FIDODevice::GetDevices(false);
		if (_devices.empty())
		{
			ResetMfa();
			SetStatus(L"Insert a registered CTAP2 USB security key. Sign-in is blocked.", query);
			return HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_AVAILABLE);
		}
		if (_devices.size() > 1 || _devices.front().HasPin())
		{
			SetMode(Mode::FIDO);
			SetStatus(_devices.size() > 1 ? L"Select a USB security key, enter its PIN, then touch it."
				: L"Enter the security-key PIN, then touch the key.", query);
			return E_FAIL;
		}
	}

	if (_selectedDevice >= _devices.size()) _selectedDevice = 0;
	SetStatus(L"Touch the USB security key to approve this sign-in.", query);
	std::string pin = Convert::ToString(_configuration->credential.fidoPin);
	FIDOSignResponse assertion;
	const int fidoStatus = _devices[_selectedDevice].Sign(_challenge->request, _challenge->origin, pin, assertion);
	if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
	if (fidoStatus != FIDO_OK)
	{
		ResetMfa();
		SetMode(Mode::USERNAME_PASSWORD);
		SetStatus(L"Security-key verification failed. A new MFA attempt is required.", query);
		return E_ACCESSDENIED;
	}
	std::wstring brokerError;
	if (!_broker.FinishAuthentication(_challenge->sessionId, assertion, brokerError))
	{
		ResetMfa();
		SetMode(Mode::USERNAME_PASSWORD);
		SetStatus(L"The Broker rejected the security-key assertion. A new MFA attempt is required.", query);
		return E_ACCESSDENIED;
	}
	_mfaComplete = true;
	_challenge.reset();
	SetStatus(L"Security key verified. Signing in…", query);
	return S_OK;
}

HRESULT CCredential::PackLogon(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
	CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization)
{
	PWSTR protectedPassword = nullptr;
	HRESULT status = ProtectIfNecessaryAndCopyPassword(_configuration->credential.password.c_str(),
		_configuration->provider.scenario, &protectedPassword);
	if (FAILED(status)) return status;
	KERB_INTERACTIVE_UNLOCK_LOGON logon{};
	status = KerbInteractiveUnlockLogonInit(
		const_cast<PWSTR>(_configuration->credential.domain.c_str()),
		const_cast<PWSTR>(_configuration->credential.username.c_str()), protectedPassword,
		_configuration->provider.scenario, &logon);
	if (SUCCEEDED(status)) status = KerbInteractiveUnlockLogonPack(logon, &serialization->rgbSerialization, &serialization->cbSerialization);
	if (protectedPassword)
	{
		SecureZeroMemory(protectedPassword, (wcslen(protectedPassword) + 1) * sizeof(wchar_t));
		CoTaskMemFree(protectedPassword);
	}
	if (FAILED(status)) return status;
	status = RetrieveNegotiateAuthPackage(&serialization->ulAuthenticationPackage);
	if (FAILED(status))
	{
		ClearPackedSerialization(serialization);
		return status;
	}
	serialization->clsidCredentialProvider = CLSID_CSample;
	*response = CPGSR_RETURN_CREDENTIAL_FINISHED;
	return S_OK;
}

HRESULT CCredential::PackPasswordChange(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
	CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization)
{
	if (!_passwordChangeAuthorized || _configuration->credential.newPassword1.empty() ||
		_configuration->credential.newPassword1 != _configuration->credential.newPassword2) return E_INVALIDARG;
	KERB_CHANGEPASSWORD_REQUEST request{};
	request.MessageType = KerbChangePasswordMessage;
	request.Impersonating = FALSE;
	HRESULT status = UnicodeStringInitWithString(const_cast<PWSTR>(_configuration->credential.domain.c_str()), &request.DomainName);
	if (SUCCEEDED(status)) status = UnicodeStringInitWithString(const_cast<PWSTR>(_configuration->credential.username.c_str()), &request.AccountName);
	if (SUCCEEDED(status)) status = UnicodeStringInitWithString(const_cast<PWSTR>(_configuration->credential.password.c_str()), &request.OldPassword);
	if (SUCCEEDED(status)) status = UnicodeStringInitWithString(const_cast<PWSTR>(_configuration->credential.newPassword1.c_str()), &request.NewPassword);
	if (SUCCEEDED(status)) status = KerbChangePasswordPack(request, &serialization->rgbSerialization, &serialization->cbSerialization);
	if (SUCCEEDED(status)) status = RetrieveNegotiateAuthPackage(&serialization->ulAuthenticationPackage);
	if (FAILED(status))
	{
		ClearPackedSerialization(serialization);
		return status;
	}
	serialization->clsidCredentialProvider = CLSID_CSample;
	*response = CPGSR_RETURN_CREDENTIAL_FINISHED;
	return S_OK;
}

HRESULT CCredential::GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* response,
	CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* serialization, PWSTR* statusText,
	CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
{
	if (!response || !serialization || !statusText || !statusIcon) return E_INVALIDARG;
	*response = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
	*statusText = nullptr;
	*statusIcon = CPSI_NONE;
	ZeroMemory(serialization, sizeof(*serialization));
	if (_configuration->mode == Mode::CHANGE_PASSWORD)
	{
		const HRESULT status = PackPasswordChange(response, serialization);
		if (FAILED(status))
		{
			SHStrDupW(L"The new passwords must match and may not be empty.", statusText);
			*statusIcon = CPSI_ERROR;
		}
		return S_OK;
	}
	if (!_mfaComplete)
	{
		SHStrDupW(L"Complete local security-key verification before signing in.", statusText);
		*statusIcon = CPSI_ERROR;
		return S_OK;
	}
	return PackLogon(response, serialization);
}

HRESULT CCredential::ReportResult(NTSTATUS status, NTSTATUS substatus, PWSTR* statusText,
	CREDENTIAL_PROVIDER_STATUS_ICON* statusIcon)
{
	if (!statusText || !statusIcon) return E_INVALIDARG;
	*statusText = nullptr;
	*statusIcon = CPSI_NONE;
	if (status == STATUS_SUCCESS)
	{
		ResetMfa();
		_passwordChangeAuthorized = false;
		_configuration->ClearSecrets();
		ReplaceFieldString(_strings[FID_PASSWORD], L"");
		ReplaceFieldString(_strings[FID_NEW_PASS_1], L"");
		ReplaceFieldString(_strings[FID_NEW_PASS_2], L"");
		return S_OK;
	}
	if (status == STATUS_PASSWORD_MUST_CHANGE || status == STATUS_PASSWORD_EXPIRED ||
		substatus == STATUS_PASSWORD_MUST_CHANGE || substatus == STATUS_PASSWORD_EXPIRED)
	{
		_passwordChangeAuthorized = _mfaComplete;
		_mfaComplete = false;
		SetMode(Mode::CHANGE_PASSWORD);
		SetStatus(L"Your Windows password must be changed. Enter a new password twice.");
		SHStrDupW(L"Your Windows password must be changed.", statusText);
		*statusIcon = CPSI_WARNING;
		return S_OK;
	}
	ResetMfa();
	SetMode(Mode::USERNAME_PASSWORD);
	_configuration->ClearSecrets();
	ReplaceFieldString(_strings[FID_PASSWORD], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_1], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_2], L"");
	SetStatus(L"Windows rejected the password. Complete a new password + security-key attempt.");
	SHStrDupW(L"Sign-in failed. Re-enter the password and complete MFA again.", statusText);
	*statusIcon = CPSI_ERROR;
	return S_OK;
}

HRESULT CCredential::FullReset()
{
	ResetMfa();
	_passwordChangeAuthorized = false;
	_configuration->ClearSecrets();
	ReplaceFieldString(_strings[FID_PASSWORD], L"");
	ReplaceFieldString(_strings[FID_FIDO_PIN], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_1], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_2], L"");
	SetMode(Mode::USERNAME_PASSWORD);
	SetStatus(L"Enter a local account password.");
	return S_OK;
}
