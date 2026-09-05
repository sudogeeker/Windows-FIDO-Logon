#include "BrokerClient.h"
#include "Convert.h"
#include "FIDODevice.h"
#include "FIDOException.h"
#include "FIDORegistrationRequest.h"
#include "LocalAccount.h"

#include <Windows.h>
#include <shellapi.h>
#include <optional>
#include <string>
#include <vector>

namespace
{
	constexpr int IDC_KEYS = 100;
	constexpr int IDC_ADD_KEY = 101;
	constexpr int IDC_TEST_KEY = 102;
	constexpr int IDC_REMOVE_KEY = 103;
	constexpr int IDC_ENABLE = 104;
	constexpr int IDC_DISABLE = 105;
	constexpr int IDC_REFRESH = 106;

	void ClearSecret(std::wstring& value)
	{
		if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
		value.clear();
	}

	struct PromptState
	{
		std::wstring message;
		std::wstring value;
		bool password = false;
		bool accepted = false;
		HWND edit = nullptr;
	};

	LRESULT CALLBACK PromptWindow(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
	{
		auto state = reinterpret_cast<PromptState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
		if (message == WM_NCCREATE)
		{
			state = static_cast<PromptState*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
			SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
		}
		switch (message)
		{
		case WM_CREATE:
		{
			CreateWindowW(L"STATIC", state->message.c_str(), WS_CHILD | WS_VISIBLE, 16, 16, 420, 44, window, nullptr, nullptr, nullptr);
			state->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
				ES_AUTOHSCROLL | (state->password ? ES_PASSWORD : 0), 16, 68, 420, 25, window, nullptr, nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, 270, 112, 78, 28,
				window, reinterpret_cast<HMENU>(IDOK), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 358, 112, 78, 28,
				window, reinterpret_cast<HMENU>(IDCANCEL), nullptr, nullptr);
			SetFocus(state->edit);
			return 0;
		}
		case WM_COMMAND:
			if (LOWORD(wParam) == IDOK)
			{
				const int length = GetWindowTextLengthW(state->edit);
				state->value.resize(static_cast<size_t>(length) + 1);
				GetWindowTextW(state->edit, state->value.data(), length + 1);
				state->value.resize(static_cast<size_t>(length));
				state->accepted = true;
				DestroyWindow(window);
				return 0;
			}
			if (LOWORD(wParam) == IDCANCEL) { DestroyWindow(window); return 0; }
			break;
		case WM_CLOSE: DestroyWindow(window); return 0;
		}
		return DefWindowProcW(window, message, wParam, lParam);
	}

	bool Prompt(HWND owner, const std::wstring& title, const std::wstring& message, bool password, std::wstring& value)
	{
		static bool registered = false;
		if (!registered)
		{
			WNDCLASSW cls{};
			cls.lpfnWndProc = PromptWindow;
			cls.hInstance = GetModuleHandleW(nullptr);
			cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
			cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
			cls.lpszClassName = L"WindowsFidoLogonPrompt";
			if (!RegisterClassW(&cls) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return false;
			registered = true;
		}
		PromptState state{ message, L"", password };
		EnableWindow(owner, FALSE);
		HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME, L"WindowsFidoLogonPrompt", title.c_str(),
			WS_POPUP | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT, 470, 190, owner, nullptr,
			GetModuleHandleW(nullptr), &state);
		if (!dialog) { EnableWindow(owner, TRUE); return false; }
		ShowWindow(dialog, SW_SHOW);
		MSG msg{};
		while (IsWindow(dialog) && GetMessageW(&msg, nullptr, 0, 0) > 0)
		{
			if (!IsDialogMessageW(dialog, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
		}
		EnableWindow(owner, TRUE);
		SetForegroundWindow(owner);
		if (state.accepted) value = std::move(state.value);
		return state.accepted;
	}

	void Error(HWND owner, const std::wstring& text)
	{
		MessageBoxW(owner, text.c_str(), L"Windows FIDO Logon", MB_OK | MB_ICONERROR);
	}

	std::optional<size_t> ChooseDevice(HWND owner, const std::vector<FIDODevice>& devices, const std::wstring& purpose)
	{
		if (devices.empty()) { Error(owner, L"No compatible CTAP2 ES256 USB security key was found."); return std::nullopt; }
		if (devices.size() == 1) return 0;
		std::wstring message = purpose + L"\r\n";
		for (size_t index = 0; index < devices.size(); ++index)
			message += std::to_wstring(index + 1) + L". " + Convert::ToWString(devices[index].ToString()) + L"\r\n";
		message += L"Enter the device number:";
		std::wstring choice;
		if (!Prompt(owner, L"Choose security key", message, false, choice)) return std::nullopt;
		try
		{
			const size_t index = static_cast<size_t>(std::stoul(choice));
			if (index >= 1 && index <= devices.size()) return index - 1;
		}
		catch (...) {}
		Error(owner, L"Invalid device number.");
		return std::nullopt;
	}

	bool SignChallenge(HWND owner, const localfido::AuthenticationChallenge& challenge,
		FIDODevice& device, std::string& retainedPin, FIDOSignResponse& assertion)
	{
		std::wstring pin;
		if (device.HasPin() && retainedPin.empty())
		{
			if (!Prompt(owner, L"Security-key PIN", L"Enter the PIN for the selected USB security key:", true, pin)) return false;
			retainedPin = Convert::ToString(pin);
			ClearSecret(pin);
		}
		const int status = device.Sign(challenge.request, challenge.origin, retainedPin, assertion);
		if (status != FIDO_OK)
		{
			Error(owner, L"Security-key operation failed: " + Convert::ToWString(fido_strerr(status)));
			return false;
		}
		return true;
	}

	struct AppState
	{
		HWND window = nullptr;
		HWND list = nullptr;
		std::wstring username;
		std::wstring sid;
		localfido::AccountStatus status;
		localfido::BrokerClient broker;
	};

	bool Refresh(AppState& app)
	{
		std::wstring error;
		if (!app.broker.GetStatus(app.sid, app.status, error)) { Error(app.window, error); return false; }
		SendMessageW(app.list, LB_RESETCONTENT, 0, 0);
		for (const auto& item : app.status.credentials)
		{
			std::wstring line = Convert::ToWString(item.label) + L"  [" + Convert::ToWString(item.aaguid) + L"]";
			SendMessageW(app.list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line.c_str()));
		}
		const std::wstring title = L"Windows FIDO Logon — " + app.username +
			(app.status.enforced ? L" — MFA enforced" : L" — MFA not enforced");
		SetWindowTextW(app.window, title.c_str());
		return true;
	}

	bool AddKey(AppState& app)
	{
		std::wstring password, label;
		if (!Prompt(app.window, L"Authorize enrollment", L"Enter your current Windows password:", true, password)) return false;
		if (!Prompt(app.window, L"Name security key", L"Enter a label for this security key:", false, label)) { ClearSecret(password); return false; }
		localfido::AuthenticationChallenge authorization;
		localfido::RegistrationChallenge registration;
		std::wstring error;
		if (!app.broker.BeginRegistration(app.sid, app.username, password, Convert::ToString(label), authorization, registration, error))
		{
			ClearSecret(password); Error(app.window, error); return false;
		}
		ClearSecret(password);
		if (authorization.enforced)
		{
			auto devices = FIDODevice::GetDevices();
			auto selected = ChooseDevice(app.window, devices, L"Choose an already-registered key to authorize adding another key.");
			if (!selected) return false;
			std::string pin;
			FIDOSignResponse assertion;
			if (!SignChallenge(app.window, authorization, devices[*selected], pin, assertion)) { if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size()); return false; }
			if (!app.broker.AuthorizeRegistration(authorization.sessionId, assertion, registration, error))
			{
				if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size()); Error(app.window, error); return false;
			}
			if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
		}

		auto devices = FIDODevice::GetDevices();
		auto selected = ChooseDevice(app.window, devices, L"Choose the new key to register.");
		if (!selected) return false;
		FIDODevice& device = devices[*selected];
		std::string pin;
		if (!device.HasPin())
		{
			std::wstring first, second;
			if (!Prompt(app.window, L"Set security-key PIN", L"This key needs a PIN for user verification. Enter a new PIN:", true, first) ||
				!Prompt(app.window, L"Confirm security-key PIN", L"Enter the same new PIN again:", true, second))
			{
				ClearSecret(first); ClearSecret(second); return false;
			}
			if (first != second) { ClearSecret(first); ClearSecret(second); Error(app.window, L"The PIN values did not match."); return false; }
			pin = Convert::ToString(first);
			try { device.SetPin(pin); }
			catch (const std::exception& exception) { ClearSecret(first); ClearSecret(second); SecureZeroMemory(pin.data(), pin.size()); Error(app.window, Convert::ToWString(exception.what())); return false; }
			ClearSecret(first); ClearSecret(second);
		}
		else
		{
			std::wstring entered;
			if (!Prompt(app.window, L"Security-key PIN", L"Enter the PIN for the new USB security key:", true, entered)) return false;
			pin = Convert::ToString(entered);
			ClearSecret(entered);
		}

		FIDORegistrationRequest request;
		request.rpId = registration.rpId;
		request.rpName = "Windows FIDO Logon";
		request.userName = Convert::ToString(app.username);
		request.userDisplayName = request.userName;
		request.userId = registration.userId;
		request.challenge = registration.challenge;
		request.type = "webauthn";
		request.pubKeyCredParams = { {"public-key", COSE_ES256} };
		request.excludeCredentials = registration.excludeCredentials;
		request.residentKey = true;
		request.userVerification = true;
		try
		{
			auto created = device.Register(request, registration.origin, pin);
			if (!created) throw std::runtime_error("The authenticator did not return a credential.");
			localfido::AuthenticationChallenge proof;
			if (!app.broker.CommitRegistration(registration.sessionId, Convert::ToString(label), created->attestationObject,
				created->clientDataJSON, proof, error)) throw std::runtime_error(Convert::ToString(error));
			FIDOSignResponse proofAssertion;
			if (!SignChallenge(app.window, proof, device, pin, proofAssertion)) throw std::runtime_error("Proof of possession failed.");
			if (!app.broker.FinishRegistration(proof.sessionId, proofAssertion, error)) throw std::runtime_error(Convert::ToString(error));
		}
		catch (const std::exception& exception)
		{
			if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
			Error(app.window, Convert::ToWString(exception.what()));
			return false;
		}
		if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
		MessageBoxW(app.window, L"Security key registered and proof of possession verified.", L"Windows FIDO Logon", MB_OK | MB_ICONINFORMATION);
		return Refresh(app);
	}

	bool TestKey(AppState& app)
	{
		localfido::AuthenticationChallenge challenge;
		std::wstring error;
		if (!app.broker.BeginTest(app.sid, challenge, error)) { Error(app.window, error); return false; }
		auto devices = FIDODevice::GetDevices();
		auto selected = ChooseDevice(app.window, devices, L"Choose a registered key to test.");
		if (!selected) return false;
		std::string pin;
		FIDOSignResponse assertion;
		const bool signedOk = SignChallenge(app.window, challenge, devices[*selected], pin, assertion);
		if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
		if (!signedOk) return false;
		if (!app.broker.FinishAuthentication(challenge.sessionId, assertion, error)) { Error(app.window, error); return false; }
		MessageBoxW(app.window, L"The security key is registered and valid.", L"Windows FIDO Logon", MB_OK | MB_ICONINFORMATION);
		return Refresh(app);
	}

	bool RemoveKey(AppState& app)
	{
		const LRESULT selectedItem = SendMessageW(app.list, LB_GETCURSEL, 0, 0);
		if (selectedItem == LB_ERR || static_cast<size_t>(selectedItem) >= app.status.credentials.size())
		{
			Error(app.window, L"Select a security key to remove."); return false;
		}
		std::wstring password;
		if (!Prompt(app.window, L"Authorize removal", L"Enter your current Windows password:", true, password)) return false;
		localfido::AuthenticationChallenge authorization;
		std::wstring error;
		if (!app.broker.BeginRemoval(app.sid, app.username, password,
			app.status.credentials[static_cast<size_t>(selectedItem)].credentialId, authorization, error))
		{
			ClearSecret(password); Error(app.window, error); return false;
		}
		ClearSecret(password);
		auto devices = FIDODevice::GetDevices();
		auto deviceIndex = ChooseDevice(app.window, devices, L"Choose any registered key to authorize removal.");
		if (!deviceIndex) return false;
		std::string pin;
		FIDOSignResponse assertion;
		const bool signedOk = SignChallenge(app.window, authorization, devices[*deviceIndex], pin, assertion);
		if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
		if (!signedOk) return false;
		if (!app.broker.FinishRemoval(authorization.sessionId, assertion, error)) { Error(app.window, error); return false; }
		return Refresh(app);
	}

	void ElevatePolicyChange(AppState& app, bool enabled)
	{
		wchar_t executable[MAX_PATH]{};
		GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
		const std::wstring parameters = L"--set-enforcement \"" + app.sid + L"\" " + (enabled ? L"1" : L"0");
		if (reinterpret_cast<INT_PTR>(ShellExecuteW(app.window, L"runas", executable, parameters.c_str(), nullptr, SW_SHOWNORMAL)) <= 32)
			Error(app.window, L"Administrator elevation was cancelled or failed.");
	}

	LRESULT CALLBACK MainWindow(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
	{
		auto app = reinterpret_cast<AppState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
		if (message == WM_NCCREATE)
		{
			app = static_cast<AppState*>(reinterpret_cast<CREATESTRUCTW*>(lParam)->lpCreateParams);
			app->window = window;
			SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(app));
		}
		switch (message)
		{
		case WM_CREATE:
			CreateWindowW(L"STATIC", L"Registered USB FIDO2 security keys", WS_CHILD | WS_VISIBLE, 16, 16, 430, 24, window, nullptr, nullptr, nullptr);
			app->list = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LBS_NOTIFY,
				16, 44, 548, 220, window, reinterpret_cast<HMENU>(IDC_KEYS), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Add key", WS_CHILD | WS_VISIBLE, 16, 280, 88, 30, window, reinterpret_cast<HMENU>(IDC_ADD_KEY), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Test key", WS_CHILD | WS_VISIBLE, 112, 280, 88, 30, window, reinterpret_cast<HMENU>(IDC_TEST_KEY), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Remove", WS_CHILD | WS_VISIBLE, 208, 280, 88, 30, window, reinterpret_cast<HMENU>(IDC_REMOVE_KEY), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Enable MFA", WS_CHILD | WS_VISIBLE, 304, 280, 96, 30, window, reinterpret_cast<HMENU>(IDC_ENABLE), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Disable MFA", WS_CHILD | WS_VISIBLE, 408, 280, 96, 30, window, reinterpret_cast<HMENU>(IDC_DISABLE), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE, 512, 280, 70, 30, window, reinterpret_cast<HMENU>(IDC_REFRESH), nullptr, nullptr);
			Refresh(*app);
			return 0;
		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
			case IDC_ADD_KEY: AddKey(*app); break;
			case IDC_TEST_KEY: TestKey(*app); break;
			case IDC_REMOVE_KEY: RemoveKey(*app); break;
			case IDC_ENABLE: ElevatePolicyChange(*app, true); break;
			case IDC_DISABLE: ElevatePolicyChange(*app, false); break;
			case IDC_REFRESH: Refresh(*app); break;
			}
			return 0;
		case WM_DESTROY: PostQuitMessage(0); return 0;
		}
		return DefWindowProcW(window, message, wParam, lParam);
	}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc == 4 && _wcsicmp(argv[1], L"--set-enforcement") == 0)
	{
		localfido::BrokerClient broker;
		std::wstring error;
		const bool ok = broker.SetEnforcement(argv[2], wcstol(argv[3], nullptr, 10) != 0, error);
		LocalFree(argv);
		MessageBoxW(nullptr, ok ? L"MFA policy was updated." : error.c_str(), L"Windows FIDO Logon", ok ? MB_ICONINFORMATION : MB_ICONERROR);
		return ok ? 0 : 1;
	}
	if (argv) LocalFree(argv);

	AppState app;
	DWORD errorCode = ERROR_SUCCESS;
	if (!localfido::GetCurrentProcessUser(app.username, app.sid, &errorCode))
	{
		Error(nullptr, L"Unable to identify the current Windows account.");
		return 1;
	}
	WNDCLASSW cls{};
	cls.lpfnWndProc = MainWindow;
	cls.hInstance = instance;
	cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	cls.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
	cls.lpszClassName = L"WindowsFidoLogonManager";
	if (!RegisterClassW(&cls)) return 1;
	HWND window = CreateWindowW(cls.lpszClassName, L"Windows FIDO Logon", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
		CW_USEDEFAULT, CW_USEDEFAULT, 610, 365, nullptr, nullptr, instance, &app);
	if (!window) return 1;
	ShowWindow(window, show);
	UpdateWindow(window);
	MSG message{};
	while (GetMessageW(&message, nullptr, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
	return static_cast<int>(message.wParam);
}
