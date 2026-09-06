// Exercise credential callbacks without authenticating or changing MFA policy.
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include "core/CCredential.h"
#include "Localization.h"

#include <iostream>
#include <stdexcept>

HINSTANCE g_hinst = nullptr;
void DllAddRef() noexcept {}
void DllRelease() noexcept {}

namespace
{
	void Require(bool condition, const char* message)
	{
		if (!condition) throw std::runtime_error(message);
	}

	struct CredentialEvents : ICredentialProviderCredentialEvents
	{
		std::wstring visiblePin;
		std::wstring smallText;
		ULONG references = 1;
		HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
		{
			if (!value) return E_INVALIDARG;
			*value = nullptr;
			if (iid != IID_IUnknown && iid != __uuidof(ICredentialProviderCredentialEvents)) return E_NOINTERFACE;
			*value = static_cast<ICredentialProviderCredentialEvents*>(this);
			AddRef();
			return S_OK;
		}
		ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
		ULONG STDMETHODCALLTYPE Release() override { return --references; }
		HRESULT STDMETHODCALLTYPE SetFieldState(ICredentialProviderCredential*, DWORD field, CREDENTIAL_PROVIDER_FIELD_STATE state) override
		{
			if (field == FID_SMALL_TEXT) Require(state == CPFS_DISPLAY_IN_SELECTED_TILE, "small-text area was hidden");
			return S_OK;
		}
		HRESULT STDMETHODCALLTYPE SetFieldInteractiveState(ICredentialProviderCredential*, DWORD, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE) override { return S_OK; }
		HRESULT STDMETHODCALLTYPE SetFieldString(ICredentialProviderCredential*, DWORD field, LPCWSTR text) override
		{
			if (field == FID_FIDO_PIN) visiblePin = text ? text : L"";
			if (field == FID_SMALL_TEXT) smallText = text ? text : L"";
			return S_OK;
		}
		HRESULT STDMETHODCALLTYPE SetFieldCheckbox(ICredentialProviderCredential*, DWORD, BOOL, LPCWSTR) override { return S_OK; }
		HRESULT STDMETHODCALLTYPE SetFieldBitmap(ICredentialProviderCredential*, DWORD, HBITMAP) override { return S_OK; }
		HRESULT STDMETHODCALLTYPE SetFieldComboBoxSelectedItem(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
		HRESULT STDMETHODCALLTYPE DeleteFieldComboBoxItem(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
		HRESULT STDMETHODCALLTYPE AppendFieldComboBoxItem(ICredentialProviderCredential*, DWORD, LPCWSTR) override { return S_OK; }
		HRESULT STDMETHODCALLTYPE SetFieldSubmitButton(ICredentialProviderCredential*, DWORD, DWORD) override { return S_OK; }
		HRESULT STDMETHODCALLTYPE OnCreatingWindow(HWND* owner) override { *owner = nullptr; return S_OK; }
	};

	struct QueryStatus : IQueryContinueWithStatus
	{
		std::wstring message;
		ULONG references = 1;
		HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
		{
			if (!value) return E_INVALIDARG;
			*value = nullptr;
			if (iid != IID_IUnknown && iid != __uuidof(IQueryContinue) && iid != __uuidof(IQueryContinueWithStatus)) return E_NOINTERFACE;
			*value = static_cast<IQueryContinueWithStatus*>(this);
			AddRef();
			return S_OK;
		}
		ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
		ULONG STDMETHODCALLTYPE Release() override { return --references; }
		HRESULT STDMETHODCALLTYPE QueryContinue() override { return S_OK; }
		HRESULT STDMETHODCALLTYPE SetStatusMessage(LPCWSTR text) override { message = text; return S_OK; }
	};

	std::wstring FieldText(CCredential& credential, DWORD field)
	{
		PWSTR text = nullptr;
		Require(SUCCEEDED(credential.GetStringValue(field, &text)), "field read failed");
		const std::wstring result = text ? text : L"";
		CoTaskMemFree(text);
		return result;
	}

	void CheckInitialTile(CCredential& credential, const CredentialEvents& events)
	{
		CREDENTIAL_PROVIDER_FIELD_STATE state;
		CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interactive;
		Require(SUCCEEDED(credential.GetFieldState(FID_SMALL_TEXT, &state, &interactive)), "field state read failed");
		Require(state == CPFS_DISPLAY_IN_SELECTED_TILE &&
			FieldText(credential, FID_SMALL_TEXT) == UiText(UiTextId::SelectUserAndPasswordPrompt),
			"tile does not start with the localized prompt");
		Require(events.smallText.empty(), "tile received an unexpected initial status message");
	}

	void TestCredentialCallbacks()
	{
		for (const auto states : { s_rgScenarioUsernamePassword, s_rgScenarioFido, s_rgScenarioChangePassword })
			Require(states[FID_SMALL_TEXT].cpfs == CPFS_DISPLAY_IN_SELECTED_TILE, "scenario hides small text");
		Require(wcscmp(s_rgScenarioCredProvFieldDescriptors[FID_SUBMIT_BUTTON].pszLabel, L"") == 0,
			"submit descriptor has a non-localized fallback");
		Require(wcscmp(UiFieldLabel(FID_SUBMIT_BUTTON), UiText(UiTextId::ContinueButton)) == 0,
			"submit descriptor does not use the localized continue label");
		Require(FID_NUM_FIELDS == 9, "LogonUI unexpectedly exposes a security-key selector");

		auto configuration = std::make_shared<Configuration>();
		CredentialEvents events;
		CCredential credential(configuration);
		Require(SUCCEEDED(credential.Initialize(s_rgScenarioCredProvFieldDescriptors,
			s_rgScenarioUsernamePassword, nullptr, nullptr, nullptr)), "credential initialization failed");
		Require(SUCCEEDED(credential.Advise(&events)), "credential advise failed");
		CheckInitialTile(credential, events);

		QueryStatus query;
		Require(credential.Connect(&query) == E_INVALIDARG, "empty password unexpectedly accepted");
		Require(!query.message.empty(), "missing-input feedback was lost");
		Require(FieldText(credential, FID_SMALL_TEXT) == query.message && events.smallText == query.message,
			"runtime status did not replace the small-text content");

		auto enterPin = [&]()
		{
			events.visiblePin = L"123456";
			Require(SUCCEEDED(credential.SetStringValue(FID_FIDO_PIN, events.visiblePin.c_str())), "PIN entry failed");
			Require(!configuration->credential.fidoPin.empty(), "test did not populate PIN");
		};
		auto checkPinCleared = [&]()
		{
			Require(configuration->credential.fidoPin.empty(), "configuration retained PIN");
			Require(FieldText(credential, FID_FIDO_PIN).empty(), "credential field retained PIN");
			Require(events.visiblePin.empty(), "LogonUI was not told to clear PIN");
		};

		struct ResultCase { NTSTATUS status; NTSTATUS substatus; UiTextId text; CREDENTIAL_PROVIDER_STATUS_ICON icon; };
		const ResultCase cases[] = {
			{ STATUS_LOGON_FAILURE, STATUS_WRONG_PASSWORD, UiTextId::PasswordVerificationFailed, CPSI_ERROR },
			{ STATUS_WRONG_PASSWORD, STATUS_SUCCESS, UiTextId::PasswordVerificationFailed, CPSI_ERROR },
			{ STATUS_LOGON_FAILURE, STATUS_SUCCESS, UiTextId::SignInFailed, CPSI_ERROR },
			{ STATUS_LOGON_FAILURE, STATUS_NO_SUCH_USER, UiTextId::SignInFailed, CPSI_ERROR },
			{ STATUS_ACCOUNT_LOCKED_OUT, STATUS_SUCCESS, UiTextId::SignInFailed, CPSI_ERROR },
			{ STATUS_ACCOUNT_DISABLED, STATUS_SUCCESS, UiTextId::SignInFailed, CPSI_ERROR },
			{ STATUS_PASSWORD_EXPIRED, STATUS_SUCCESS, UiTextId::PasswordMustChange, CPSI_WARNING },
			{ STATUS_LOGON_FAILURE, STATUS_PASSWORD_MUST_CHANGE, UiTextId::PasswordMustChange, CPSI_WARNING },
		};
		for (const auto& test : cases)
		{
			credential.FullReset();
			enterPin();
			PWSTR text = nullptr;
			CREDENTIAL_PROVIDER_STATUS_ICON icon;
			Require(SUCCEEDED(credential.ReportResult(test.status, test.substatus, &text, &icon)), "ReportResult failed");
			const bool matches = text && wcscmp(text, UiText(test.text)) == 0 && icon == test.icon;
			CoTaskMemFree(text);
			Require(matches, "wrong error text or icon for Windows status");
			checkPinCleared();
			Require(FieldText(credential, FID_SMALL_TEXT) == UiText(test.text) && events.smallText == UiText(test.text),
				"result feedback did not replace the small-text content");
		}

		for (const auto reset : { &CCredential::Disconnect, &CCredential::SetDeselected, &CCredential::FullReset })
		{
			enterPin();
			Require(SUCCEEDED((credential.*reset)()), "reset callback failed");
			checkPinCleared();
		}
		enterPin();
		PWSTR text = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON icon;
		Require(SUCCEEDED(credential.ReportResult(STATUS_SUCCESS, STATUS_SUCCESS, &text, &icon)), "success callback failed");
		Require(text == nullptr && icon == CPSI_NONE, "successful sign-in returned an error");
		checkPinCleared();
		Require(FieldText(credential, FID_SMALL_TEXT).empty() && events.smallText.empty(),
			"successful sign-in left stale small-text content");
	}
}

int main()
{
	try
	{
		TestCredentialCallbacks();
		std::cout << "Credential UI tests passed.\n";
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << error.what() << '\n';
		return 1;
	}
}
