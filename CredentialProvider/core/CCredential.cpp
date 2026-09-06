#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif

#include "CCredential.h"

#include "Convert.h"
#include "LocalAccount.h"
#include "LocalCredentialStore.h"
#include "Logger.h"
#include "Localization.h"
#include "Mode.h"
#include "guid.h"
#include "resource.h"

#include <Windows.h>
#include <fido.h>
#include <cwchar>
#include <new>
#include <utility>

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
	localfido::EnumerateLocalAccounts(_users);
	if (!_configuration->credential.username.empty())
	{
		for (DWORD index = 0; index < _users.size(); ++index)
		{
			if (_wcsicmp(_users[index].username.c_str(), _configuration->credential.username.c_str()) == 0)
			{
				_selectedUser = index;
				break;
			}
		}
	}
	else if (!_users.empty())
	{
		_selectedUser = 0;
		_configuration->credential.username = _users.front().username;
		_configuration->credential.domain = _users.front().computerName;
	}
	ReplaceFieldString(_strings[FID_LARGE_TEXT], UiText(UiTextId::Title));
	ReplaceFieldString(_strings[FID_SMALL_TEXT], UiText(UiTextId::SelectUserAndPasswordPrompt));
	ReplaceFieldString(_strings[FID_USERNAME], _configuration->credential.username.c_str());
	ReplaceFieldString(_strings[FID_PASSWORD], _configuration->credential.password.c_str());
	ReplaceFieldString(_strings[FID_SUBMIT_BUTTON], UiText(UiTextId::ContinueButton));
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
	if (!count || !selected) return E_INVALIDARG;
	if (field == FID_USERNAME)
	{
		*count = static_cast<DWORD>(_users.size());
		*selected = _selectedUser < _users.size() ? _selectedUser : 0;
		return S_OK;
	}
	return E_INVALIDARG;
}

HRESULT CCredential::GetComboBoxValueAt(DWORD field, DWORD item, PWSTR* value)
{
	if (!value) return E_INVALIDARG;
	if (field == FID_USERNAME)
	{
		if (item >= _users.size()) return E_INVALIDARG;
		return SHStrDupW(_users[item].username.c_str(), value);
	}
	return E_INVALIDARG;
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
	if (field == FID_USERNAME)
	{
		if (selected >= _users.size()) return E_INVALIDARG;
		_selectedUser = selected;
		_configuration->credential.username = _users[selected].username;
		_configuration->credential.domain = _users[selected].computerName;
		_sid = _users[selected].sidString;
		ResetMfa();
		return S_OK;
	}
	return E_INVALIDARG;
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
		if (_events)
		{
			_events->SetFieldState(this, index, _states[index].cpfs);
			_events->SetFieldInteractiveState(this, index, _states[index].cpfis);
		}
	}
	const PCWSTR submitLabel = mode == Mode::FIDO ? UiText(UiTextId::VerifyKeyButton) :
		(mode == Mode::CHANGE_PASSWORD ? UiText(UiTextId::ChangePasswordButton) : UiText(UiTextId::ContinueButton));
	ReplaceFieldString(_strings[FID_SUBMIT_BUTTON], submitLabel);
	if (_events) _events->SetFieldString(this, FID_SUBMIT_BUTTON, submitLabel);
	return S_OK;
}

void CCredential::ResetMfa()
{
	_mfaComplete = false;
	_challenge.reset();
	_devices.clear();
	_selectedDevice.reset();
	ClearPin();
	SetStatus(L"", nullptr);
}

void CCredential::ClearPin()
{
	if (!_configuration->credential.fidoPin.empty())
		SecureZeroMemory(_configuration->credential.fidoPin.data(), _configuration->credential.fidoPin.size() * sizeof(wchar_t));
	_configuration->credential.fidoPin.clear();
	// Clear the existing buffer without allocating, then clear LogonUI's copy.
	if (_strings[FID_FIDO_PIN])
		SecureZeroMemory(_strings[FID_FIDO_PIN], (wcslen(_strings[FID_FIDO_PIN]) + 1) * sizeof(wchar_t));
	if (_events) _events->SetFieldString(this, FID_FIDO_PIN, L"");
}

HRESULT CCredential::Disconnect()
{
	ClearPin();
	return S_OK;
}

HRESULT CCredential::Connect(IQueryContinueWithStatus* query)
{
	if (_configuration->mode == Mode::CHANGE_PASSWORD)
		return _passwordChangeAuthorized ? S_OK : E_ACCESSDENIED;
	if (_configuration->credential.username.empty() || _configuration->credential.password.empty())
	{
		SetStatus(UiText(UiTextId::SelectUserAndPasswordPrompt), query);
		return E_INVALIDARG;
	}

	if (!_challenge)
	{
		std::wstring username, computer, sid;
		DWORD accountError = ERROR_SUCCESS;
		if (!localfido::ResolveLocalAccount(_configuration->credential.username, username, computer, sid, &accountError))
		{
			SetStatus(UiText(UiTextId::LocalAccountsOnly), query);
			return HRESULT_FROM_WIN32(accountError);
		}
		_configuration->credential.username = username;
		_configuration->credential.domain = computer;
		_sid = sid;
		localfido::AuthenticationChallenge challenge;
		std::wstring brokerError;
		if (!_broker.BeginAuthentication(sid, challenge, brokerError))
		{
			// The Broker is the authoritative policy and challenge endpoint. A
			// transport or policy-read failure must never become password-only
			// authentication, because a failed local registry read could otherwise
			// be interpreted as "not enforced".
			SetStatus(UiText(UiTextId::SignInVerificationUnavailable), query);
			return E_ACCESSDENIED;
		}
		if (!challenge.enforced)
		{
			if (localfido::LocalCredentialStore::IsSidEnforced(sid))
			{
				SetStatus(UiText(UiTextId::MfaPolicyUnavailable), query);
				return E_ACCESSDENIED;
			}
			_mfaComplete = true;
			SetStatus(UiText(UiTextId::PreparingWindowsSignIn), query);
			return S_OK;
		}
		_challenge = std::move(challenge);
		_devices = FIDODevice::GetDevices(false);
		if (_devices.empty())
		{
			ResetMfa();
			SetStatus(UiText(UiTextId::NoSecurityKeyDetected), query);
			return HRESULT_FROM_WIN32(ERROR_DEVICE_NOT_AVAILABLE);
		}
		if (_devices.size() > 1)
		{
			SetStatus(UiText(UiTextId::TouchKey), query);
			size_t selected = 0;
			const int selectionStatus = FIDODevice::SelectByTouch(_devices, selected, [query]()
			{
				return !query || query->QueryContinue() == S_OK;
			});
			if (selectionStatus != FIDO_OK)
			{
				ResetMfa();
				SetMode(Mode::USERNAME_PASSWORD);
				SetStatus(UiText(UiTextId::KeyVerificationFailed), query);
				return E_ACCESSDENIED;
			}
			_selectedDevice = selected;
		}
		else
		{
			_selectedDevice = 0;
		}
		if (_devices[*_selectedDevice].HasPin())
		{
			SetMode(Mode::FIDO);
			SetStatus(UiText(UiTextId::EnterPinAndTouch), query);
			// A successful Connect lets LogonUI keep the newly displayed PIN fields.
			// GetSerialization will intentionally return NO_CREDENTIAL_NOT_FINISHED
			// until the security-key ceremony completes.
			return S_OK;
		}
	}

	if (!_selectedDevice || *_selectedDevice >= _devices.size())
	{
		ResetMfa();
		SetMode(Mode::USERNAME_PASSWORD);
		SetStatus(UiText(UiTextId::KeyVerificationFailed), query);
		return E_ACCESSDENIED;
	}
	SetStatus(UiText(UiTextId::TouchKey), query);
	std::string pin = Convert::ToString(_configuration->credential.fidoPin);
	ClearPin();
	FIDOSignResponse assertion;
	const int fidoStatus = _devices[*_selectedDevice].Sign(_challenge->request, _challenge->origin, pin, assertion);
	if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
	if (fidoStatus != FIDO_OK)
	{
		ResetMfa();
		SetMode(Mode::USERNAME_PASSWORD);
		SetStatus(UiText(UiTextId::KeyVerificationFailed), query);
		return E_ACCESSDENIED;
	}
	std::wstring brokerError;
	if (!_broker.FinishAuthentication(_challenge->sessionId, assertion, brokerError))
	{
		ResetMfa();
		SetMode(Mode::USERNAME_PASSWORD);
		SetStatus(UiText(UiTextId::KeyVerificationIncomplete), query);
		return E_ACCESSDENIED;
	}
	_mfaComplete = true;
	_challenge.reset();
	SetStatus(UiText(UiTextId::KeyVerified), query);
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
			const PCWSTR message = UiText(UiTextId::PasswordUpdateFailed);
			SetStatus(message, nullptr);
			SHStrDupW(message, statusText);
			*statusIcon = CPSI_ERROR;
		}
		return S_OK;
	}
	if (!_mfaComplete)
	{
		// The first password submission only changes the visible fields to the
		// PIN/key ceremony. Do not surface it as an error or require a second
		// confirmation click.
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
	ClearPin();
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
		const PCWSTR message = UiText(UiTextId::PasswordMustChange);
		SetStatus(message, nullptr);
		SHStrDupW(message, statusText);
		*statusIcon = CPSI_WARNING;
		return S_OK;
	}
	ResetMfa();
	SetMode(Mode::USERNAME_PASSWORD);
	_configuration->ClearSecrets();
	ReplaceFieldString(_strings[FID_PASSWORD], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_1], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_2], L"");
	const bool wrongPassword = status == STATUS_WRONG_PASSWORD || substatus == STATUS_WRONG_PASSWORD;
	const PCWSTR message = UiText(wrongPassword ? UiTextId::PasswordVerificationFailed : UiTextId::SignInFailed);
	SetStatus(message, nullptr);
	SHStrDupW(message, statusText);
	*statusIcon = CPSI_ERROR;
	return S_OK;
}

HRESULT CCredential::FullReset()
{
	ResetMfa();
	_passwordChangeAuthorized = false;
	_configuration->ClearSecrets();
	ReplaceFieldString(_strings[FID_PASSWORD], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_1], L"");
	ReplaceFieldString(_strings[FID_NEW_PASS_2], L"");
	SetMode(Mode::USERNAME_PASSWORD);
	SetStatus(UiText(UiTextId::SelectUserAndPasswordPrompt), nullptr);
	return S_OK;
}
