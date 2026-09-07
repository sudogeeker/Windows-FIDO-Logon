// Native user-array and credential lifecycle tests. No authentication or policy writes.
#include <ntstatus.h>
#define WIN32_NO_STATUS
#include "core/CProvider.h"
#include "Localization.h"

#include <stdexcept>
#include <wrl/client.h>

extern HRESULT CSample_CreateInstance(REFIID, void**);

namespace
{
	using Microsoft::WRL::ComPtr;
	void Check(bool ok, const char* message)
	{
		if (!ok) throw std::runtime_error(message);
	}

	struct User : ICredentialProviderUser
	{
		ULONG references = 1;
		std::wstring sid;
		GUID provider = Identity_LocalUserProvider;
		HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
		{
			if (!value) return E_INVALIDARG;
			*value = nullptr;
			if (iid != IID_IUnknown && iid != __uuidof(ICredentialProviderUser)) return E_NOINTERFACE;
			*value = static_cast<ICredentialProviderUser*>(this);
			AddRef();
			return S_OK;
		}
		ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
		ULONG STDMETHODCALLTYPE Release() override { return --references; }
		HRESULT STDMETHODCALLTYPE GetSid(PWSTR* value) override { return SHStrDupW(sid.c_str(), value); }
		HRESULT STDMETHODCALLTYPE GetProviderID(GUID* value) override { *value = provider; return S_OK; }
		HRESULT STDMETHODCALLTYPE GetStringValue(REFPROPERTYKEY, PWSTR*) override { return E_NOTIMPL; }
		HRESULT STDMETHODCALLTYPE GetValue(REFPROPERTYKEY, PROPVARIANT*) override { return E_NOTIMPL; }
	};

	struct UserArray : ICredentialProviderUserArray
	{
		ULONG references = 1;
		std::vector<User*> users;
		CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS options = CPAO_NONE;
		HRESULT countStatus = S_OK;
		HRESULT optionsStatus = S_OK;
		DWORD failAt = MAXDWORD;
		HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** value) override
		{
			if (!value) return E_INVALIDARG;
			*value = nullptr;
			if (iid != IID_IUnknown && iid != __uuidof(ICredentialProviderUserArray)) return E_NOINTERFACE;
			*value = static_cast<ICredentialProviderUserArray*>(this);
			AddRef();
			return S_OK;
		}
		ULONG STDMETHODCALLTYPE AddRef() override { return ++references; }
		ULONG STDMETHODCALLTYPE Release() override { return --references; }
		HRESULT STDMETHODCALLTYPE SetProviderFilter(REFGUID) override { return E_NOTIMPL; }
		HRESULT STDMETHODCALLTYPE GetAccountOptions(CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS* value) override
		{ *value = options; return optionsStatus; }
		HRESULT STDMETHODCALLTYPE GetCount(DWORD* value) override
		{ *value = static_cast<DWORD>(users.size()); return countStatus; }
		HRESULT STDMETHODCALLTYPE GetAt(DWORD index, ICredentialProviderUser** value) override
		{
			*value = nullptr;
			if (index == failAt) return E_FAIL;
			if (index >= users.size()) return E_INVALIDARG;
			*value = users[index];
			(*value)->AddRef();
			return S_OK;
		}
	};

	std::wstring Text(ICredentialProviderCredential* credential, DWORD field)
	{
		PWSTR value = nullptr;
		Check(SUCCEEDED(credential->GetStringValue(field, &value)), "read field failed");
		std::wstring result(value);
		CoTaskMemFree(value);
		return result;
	}

	void CheckState(ICredentialProviderCredential* credential, DWORD field,
		CREDENTIAL_PROVIDER_FIELD_STATE state, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE interactive)
	{
		CREDENTIAL_PROVIDER_FIELD_STATE actualState;
		CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE actualInteractive;
		Check(SUCCEEDED(credential->GetFieldState(field, &actualState, &actualInteractive)), "read state failed");
		Check(state == actualState && interactive == actualInteractive, "unexpected native field state/focus");
	}

	void CheckSid(ICredentialProviderCredential* credential, PCWSTR expected)
	{
		ComPtr<ICredentialProviderCredential2> v2;
		Check(SUCCEEDED(credential->QueryInterface(IID_PPV_ARGS(&v2))), "missing V2 credential interface");
		PWSTR sid = nullptr;
		const HRESULT status = v2->GetUserSid(&sid);
		const bool matches = expected ? (status == S_OK && sid && wcscmp(sid, expected) == 0) :
			(status == S_FALSE && !sid);
		CoTaskMemFree(sid);
		Check(matches, "incorrect native user SID");
		Check(v2->GetUserSid(nullptr) == E_INVALIDARG, "null SID output accepted");
		ComPtr<IConnectableCredentialProviderCredential> connectable;
		Check(SUCCEEDED(v2.As(&connectable)), "V2 lost connectable interface");
		ComPtr<IUnknown> first, second;
		Check(SUCCEEDED(v2.As(&first)) && SUCCEEDED(connectable.As(&second)) && first == second,
			"credential interfaces have different COM identities");
	}

	void CheckCount(ICredentialProvider* provider, DWORD expected)
	{
		DWORD count = MAXDWORD, selected = 0;
		BOOL automatic = TRUE;
		Check(SUCCEEDED(provider->GetCredentialCount(&count, &selected, &automatic)), "enumeration failed");
		Check(count == expected && selected == CREDENTIAL_PROVIDER_NO_DEFAULT && !automatic,
			"wrong count or provider forced a default user");
	}

	void CheckNoSerialization(ICredentialProviderCredential* credential, HRESULT expected = S_OK)
	{
		CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE response;
		CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION serialization{};
		PWSTR text = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON icon;
		Check(credential->GetSerialization(&response, &serialization, &text, &icon) == expected,
			"unexpected serialization status");
		Check(response == CPGSR_NO_CREDENTIAL_NOT_FINISHED && !serialization.rgbSerialization && !text,
			"unauthenticated/stale credential serialized");
	}

	void TestIndependentCredentials()
	{
		auto settings = std::make_shared<Configuration>();
		settings->provider.scenario = CPUS_LOGON;
		CCredential alice(settings), bob(settings), other(settings);
		Check(SUCCEEDED(alice.Initialize(s_rgScenarioCredProvFieldDescriptors, s_rgScenarioUsernamePassword,
			L"alice", L"test", nullptr, L"S-1-5-21-1-2-3-1001")), "initialize alice failed");
		Check(SUCCEEDED(bob.Initialize(s_rgScenarioCredProvFieldDescriptors, s_rgScenarioUsernamePassword,
			L"bob", L"test", nullptr, L"S-1-5-21-1-2-3-1002")), "initialize bob failed");
		Check(SUCCEEDED(other.Initialize(s_rgScenarioCredProvFieldDescriptors, s_rgScenarioUsernamePassword,
			nullptr, nullptr, nullptr)), "initialize other failed");
		auto a = static_cast<IConnectableCredentialProviderCredential*>(&alice);
		auto b = static_cast<IConnectableCredentialProviderCredential*>(&bob);
		auto o = static_cast<IConnectableCredentialProviderCredential*>(&other);
		CheckSid(a, L"S-1-5-21-1-2-3-1001");
		CheckSid(b, L"S-1-5-21-1-2-3-1002");
		CheckSid(o, nullptr);
		CheckState(a, FID_USERNAME, CPFS_HIDDEN, CPFIS_NONE);
		CheckState(a, FID_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
		CheckState(o, FID_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
		CheckState(a, FID_LARGE_TEXT, CPFS_HIDDEN, CPFIS_NONE);
		Check(Text(a, FID_SMALL_TEXT) == UiText(UiTextId::EnterPasswordPrompt), "bound-user prompt wrong");
		Check(Text(o, FID_SMALL_TEXT) == UiText(UiTextId::SelectUserAndPasswordPrompt), "other-user prompt wrong");
		Check(alice.SetStringValue(FID_USERNAME, L"bob") == E_ACCESSDENIED, "bound identity was editable");
		for (const auto field : { FID_PASSWORD, FID_FIDO_PIN, FID_NEW_PASS_1, FID_NEW_PASS_2 })
		{
			Check(SUCCEEDED(alice.SetStringValue(field, L"alice-secret")), "set alice secret failed");
			Check(Text(b, field).empty(), "secret crossed user cards");
			Check(SUCCEEDED(bob.SetStringValue(field, L"bob-secret")), "set bob secret failed");
		}
		Check(SUCCEEDED(alice.SetDeselected()), "deselect failed");
		for (const auto field : { FID_PASSWORD, FID_FIDO_PIN, FID_NEW_PASS_1, FID_NEW_PASS_2 })
		{
			Check(Text(a, field).empty(), "deselection retained a secret");
			Check(Text(b, field) == L"bob-secret", "reset crossed user cards");
		}
		Check(alice.Connect(nullptr) == E_INVALIDARG, "internal password survived deselection");
		CheckNoSerialization(a);
		Check(SUCCEEDED(bob.Disconnect()), "disconnect failed");
		Check(bob.Connect(nullptr) == E_INVALIDARG, "disconnect retained internal password");
		PWSTR statusText = nullptr;
		CREDENTIAL_PROVIDER_STATUS_ICON icon;
		Check(SUCCEEDED(alice.ReportResult(STATUS_PASSWORD_EXPIRED, STATUS_SUCCESS, &statusText, &icon)),
			"password expiry callback failed");
		CoTaskMemFree(statusText);
		CheckState(a, FID_NEW_PASS_1, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
		CheckState(b, FID_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
		DWORD adjacent = 0;
		Check(SUCCEEDED(alice.GetSubmitButtonValue(FID_SUBMIT_BUTTON, &adjacent)) && adjacent == FID_NEW_PASS_2,
			"change-password arrow is misplaced");
		Check(alice.Connect(nullptr) == E_ACCESSDENIED, "unverified expiry granted change authorization");
		alice.SetDeselected();
		CheckState(a, FID_PASSWORD, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
		other.SetStringValue(FID_USERNAME, L"alice");
		other.SetStringValue(FID_PASSWORD, L"secret");
		other.SetStringValue(FID_FIDO_PIN, L"1234");
		other.SetStringValue(FID_USERNAME, L"bob");
		Check(Text(o, FID_PASSWORD).empty() && Text(o, FID_FIDO_PIN).empty(), "username edit retained secrets");
		Check(other.Connect(nullptr) == E_INVALIDARG, "username edit retained internal password");
		CheckNoSerialization(o);
		other.SetStringValue(FID_USERNAME, L"DOMAIN\\user");
		other.SetStringValue(FID_PASSWORD, L"not-a-password");
		Check(FAILED(other.Connect(nullptr)) && Text(o, FID_SMALL_TEXT) == UiText(UiTextId::LocalAccountsOnly),
			"other-user entry accepted a domain account");
	}
}

void TestProviderEnumeration()
{
	TestIndependentCredentials();
	User local, connected, missing;
	std::wstring username, computer;
	Check(localfido::GetCurrentProcessUser(username, local.sid) &&
		localfido::ResolveLocalSid(local.sid, username, computer), "test requires a local Windows account");
	connected.sid = local.sid;
	connected.provider = GUID_NULL;
	missing.sid = L"S-1-5-21-1-2-3-4294967294";
	UserArray array, empty;
	array.users = { &local, &connected, &missing, &local };
	ComPtr<ICredentialProvider> provider;
	Check(SUCCEEDED(CSample_CreateInstance(IID_PPV_ARGS(&provider))), "create provider failed");
	ComPtr<ICredentialProviderSetUserArray> receiver;
	Check(SUCCEEDED(provider.As(&receiver)), "missing user-array interface");
	Check(SUCCEEDED(provider->SetUsageScenario(CPUS_LOGON, 0)), "local logon rejected");
	CheckCount(provider.Get(), 0);
	Check(SUCCEEDED(receiver->SetUserArray(&array)) && array.references == 2, "user array was not retained");
	CheckCount(provider.Get(), 1);
	CheckCount(provider.Get(), 1);
	Check(local.references == 1 && connected.references == 1 && missing.references == 1, "user reference leaked");
	ComPtr<ICredentialProviderCredential> credential;
	Check(SUCCEEDED(provider->GetCredentialAt(0, &credential)), "missing user credential");
	CheckSid(credential.Get(), local.sid.c_str());
	ComPtr<ICredentialProviderCredential> invalid;
	Check(provider->GetCredentialAt(1, &invalid) == E_INVALIDARG && !invalid, "invalid index accepted");
	for (const auto field : { FID_LOGO, FID_PROVIDER_LABEL })
	{
		CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* descriptor = nullptr;
		Check(SUCCEEDED(provider->GetFieldDescriptorAt(field, &descriptor)), "descriptor copy failed");
		Check(descriptor->guidFieldType == (field == FID_LOGO ? CPFG_CREDENTIAL_PROVIDER_LOGO : CPFG_CREDENTIAL_PROVIDER_LABEL),
			"native logo/label GUID lost during copying");
		CoTaskMemFree(descriptor->pszLabel);
		CoTaskMemFree(descriptor);
	}
	Check(Text(credential.Get(), FID_PROVIDER_LABEL) == UiText(UiTextId::ProviderLabel), "provider label missing");
	credential->SetStringValue(FID_PASSWORD, L"discard-me");
	Check(SUCCEEDED(receiver->SetUserArray(&empty)) && array.references == 1, "old array reference leaked");
	CheckCount(provider.Get(), 0);
	Check(Text(credential.Get(), FID_PASSWORD).empty(), "retired card retained password");
	Check(credential->SetStringValue(FID_PASSWORD, L"new") == E_UNEXPECTED, "retired card accepted input");
	CheckNoSerialization(credential.Get(), E_UNEXPECTED);
	ComPtr<IConnectableCredentialProviderCredential> old;
	credential.As(&old);
	Check(old->Connect(nullptr) == E_UNEXPECTED, "retired card could authenticate");
	for (auto options : { CPAO_NONE, CPAO_EMPTY_CONNECTED, CPAO_EMPTY_LOCAL,
		static_cast<CREDENTIAL_PROVIDER_ACCOUNT_OPTIONS>(CPAO_EMPTY_LOCAL | CPAO_EMPTY_CONNECTED) })
	{
		empty.options = options;
		receiver->SetUserArray(&empty);
		CheckCount(provider.Get(), (options & CPAO_EMPTY_LOCAL) ? 1 : 0);
		if (options & CPAO_EMPTY_LOCAL)
		{
			ComPtr<ICredentialProviderCredential> other;
			Check(SUCCEEDED(provider->GetCredentialAt(0, &other)), "other-user missing");
			CheckSid(other.Get(), nullptr);
			CheckState(other.Get(), FID_USERNAME, CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED);
		}
	}
	array.options = CPAO_EMPTY_LOCAL;
	receiver->SetUserArray(&array);
	CheckCount(provider.Get(), 2);
	array.failAt = 1;
	receiver->SetUserArray(&array);
	DWORD count = 55, selected = 0;
	BOOL automatic = TRUE;
	Check(FAILED(provider->GetCredentialCount(&count, &selected, &automatic)) && count == 0,
		"failed enumeration exposed a partial list");
	array.failAt = MAXDWORD;
	CheckCount(provider.Get(), 2);
	array.optionsStatus = E_FAIL;
	receiver->SetUserArray(&array);
	Check(FAILED(provider->GetCredentialCount(&count, &selected, &automatic)) && count == 0,
		"failed policy read exposed credentials");
	array.optionsStatus = S_OK;
	array.countStatus = E_FAIL;
	receiver->SetUserArray(&array);
	Check(FAILED(provider->GetCredentialCount(&count, &selected, &automatic)) && count == 0,
		"failed user count exposed credentials");
	array.countStatus = S_OK;
	Check(SUCCEEDED(provider->SetUsageScenario(CPUS_UNLOCK_WORKSTATION, 0)), "unlock rejected");
	CheckCount(provider.Get(), 2);
	Check(provider->SetUsageScenario(CPUS_CREDUI, 0) == E_NOTIMPL, "CredUI became supported");
	Check(FAILED(provider->GetCredentialCount(&count, &selected, &automatic)) && count == 0,
		"unsupported scenario exposed credentials");
	receiver->SetUserArray(nullptr);
	Check(array.references == 1 && empty.references == 1, "array COM reference leaked");

	// Resolve a real account name against the wrong bound SID, stopping before Broker I/O.
	auto settings = std::make_shared<Configuration>();
	CCredential mismatch(settings);
	Check(SUCCEEDED(mismatch.Initialize(s_rgScenarioCredProvFieldDescriptors, s_rgScenarioUsernamePassword,
		username.c_str(), computer.c_str(), L"not-a-password", missing.sid.c_str())), "mismatch init failed");
	Check(mismatch.Connect(nullptr) == E_ACCESSDENIED, "bound SID mismatch accepted");
	CheckNoSerialization(static_cast<IConnectableCredentialProviderCredential*>(&mismatch));
}
