#include "BrokerClient.h"
#include "Convert.h"
#include "FIDODevice.h"
#include "FIDOException.h"
#include "FIDORegistrationRequest.h"
#include "LocalAccount.h"

#include <Windows.h>
#include <shellapi.h>
#include <algorithm>
#include <cstdlib>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
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
	constexpr int IDI_APP_ICON = 101;
	constexpr wchar_t kOurFilterGuid[] = L"{54B25B17-C7AE-4C2B-B3C4-E3B29A73D9B1}";
	constexpr wchar_t kFilterRegistry[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters";

	struct FilterConflict
	{
		std::wstring clsid;
		std::wstring name;
	};

	std::optional<FilterConflict> FindConflictingFilter()
	{
		HKEY key = nullptr;
		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kFilterRegistry, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
			return std::nullopt;
		for (DWORD index = 0;; ++index)
		{
			wchar_t name[128]{};
			DWORD length = ARRAYSIZE(name);
			const LONG status = RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
			if (status == ERROR_NO_MORE_ITEMS) break;
			if (status != ERROR_SUCCESS) continue;
			if (_wcsicmp(name, kOurFilterGuid) == 0) continue;
			HKEY filter = nullptr;
			std::wstring displayName = L"Unknown provider filter";
			if (RegOpenKeyExW(key, name, 0, KEY_READ | KEY_WOW64_64KEY, &filter) == ERROR_SUCCESS)
			{
				wchar_t value[256]{};
				DWORD bytes = sizeof(value);
				DWORD type = 0;
				if (RegQueryValueExW(filter, nullptr, nullptr, &type, reinterpret_cast<LPBYTE>(value), &bytes) == ERROR_SUCCESS &&
					(type == REG_SZ || type == REG_EXPAND_SZ) && value[0] != L'\0')
					displayName = value;
				RegCloseKey(filter);
			}
			RegCloseKey(key);
			return FilterConflict{ name, displayName };
		}
		RegCloseKey(key);
		return std::nullopt;
	}

	int DpiFor(HWND window)
	{
		const auto function = reinterpret_cast<UINT(WINAPI*)(HWND)>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "GetDpiForWindow"));
		return function && window ? static_cast<int>(function(window)) : 96;
	}

	int Scale(HWND window, int value)
	{
		return MulDiv(value, DpiFor(window), 96);
	}

	HMENU ControlId(int value)
	{
		return reinterpret_cast<HMENU>(static_cast<INT_PTR>(value));
	}

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
				window, ControlId(IDOK), nullptr, nullptr);
			CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 358, 112, 78, 28,
				window, ControlId(IDCANCEL), nullptr, nullptr);
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
		HWND subtitle = nullptr;
		HWND addButton = nullptr;
		HWND testButton = nullptr;
		HWND removeButton = nullptr;
		HWND enableButton = nullptr;
		HWND disableButton = nullptr;
		HWND refreshButton = nullptr;
		std::wstring username;
		std::wstring sid;
		localfido::AccountStatus status;
		localfido::BrokerClient broker;
		HFONT uiFont = nullptr;
		HFONT titleFont = nullptr;
		HICON logo = nullptr;
	};

	void SetControlFont(HWND control, HFONT font)
	{
		if (control && font) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
	}

	void LayoutMainWindow(AppState& app, int width, int height)
	{
		const int margin = Scale(app.window, 24);
		const int headerHeight = Scale(app.window, 112);
		const int gap = Scale(app.window, 12);
		const int buttonHeight = Scale(app.window, 38);
		const int listTop = headerHeight + Scale(app.window, 26);
		const int listBottom = height - Scale(app.window, 92);
		const int contentWidth = (width - margin * 2);
		MoveWindow(app.list, margin, listTop, contentWidth, std::max(Scale(app.window, 100), listBottom - listTop), TRUE);

		const int buttonTop = height - margin - buttonHeight;
		const int buttonWidth = (contentWidth - gap * 2) / 3;
		MoveWindow(app.addButton, margin, buttonTop, buttonWidth, buttonHeight, TRUE);
		MoveWindow(app.testButton, margin + buttonWidth + gap, buttonTop, buttonWidth, buttonHeight, TRUE);
		MoveWindow(app.removeButton, margin + (buttonWidth + gap) * 2, buttonTop, buttonWidth, buttonHeight, TRUE);
		const int secondRowTop = buttonTop - gap - buttonHeight;
		MoveWindow(app.enableButton, margin, secondRowTop, buttonWidth, buttonHeight, TRUE);
		MoveWindow(app.disableButton, margin + buttonWidth + gap, secondRowTop, buttonWidth, buttonHeight, TRUE);
		MoveWindow(app.refreshButton, margin + (buttonWidth + gap) * 2, secondRowTop, buttonWidth, buttonHeight, TRUE);
		MoveWindow(app.subtitle, margin, headerHeight - Scale(app.window, 38), contentWidth, Scale(app.window, 24), TRUE);
	}

	void ApplyWindowFonts(AppState& app)
	{
		const int dpi = DpiFor(app.window);
		if (app.uiFont) DeleteObject(app.uiFont);
		if (app.titleFont) DeleteObject(app.titleFont);
		app.uiFont = CreateFontW(-MulDiv(10, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
		app.titleFont = CreateFontW(-MulDiv(18, dpi, 72), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
		for (HWND control : { app.list, app.subtitle, app.addButton, app.testButton, app.removeButton, app.enableButton, app.disableButton, app.refreshButton })
			SetControlFont(control, app.uiFont);
	}

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
		const std::wstring summary = L"Signed in as " + app.username + L"  |  " +
			std::to_wstring(app.status.credentials.size()) + (app.status.credentials.size() == 1 ? L" registered key" : L" registered keys") +
			(app.status.enforced ? L"  |  MFA enabled" : L"  |  MFA disabled");
		SetWindowTextW(app.subtitle, summary.c_str());
		SetWindowTextW(app.window, L"Windows FIDO Logon");
		InvalidateRect(app.window, nullptr, TRUE);
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
		if (enabled && app.status.credentials.empty())
		{
			Error(app.window, L"Register at least one security key before enabling MFA.");
			return;
		}
		bool allowFilterConflict = false;
		if (enabled && app.status.credentials.size() == 1)
		{
			const int answer = MessageBoxW(app.window,
				L"Only one security key is registered. If it is lost or damaged, you may be locked out.\r\n\r\nDo you want to enable MFA anyway?",
				L"Enable MFA with one key", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
			if (answer != IDYES) return;
		}
		if (enabled)
		{
			if (const auto conflict = FindConflictingFilter())
			{
				const std::wstring warning = L"Another Credential Provider Filter is registered:\r\n" + conflict->name +
					L"\r\n" + conflict->clsid +
					L"\r\n\r\nMultiple filters may hide sign-in tiles unexpectedly. Continue and enable MFA anyway?";
				if (MessageBoxW(app.window, warning.c_str(), L"Credential Provider Filter conflict", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
					return;
				allowFilterConflict = true;
			}
		}
		wchar_t executable[MAX_PATH]{};
		GetModuleFileNameW(nullptr, executable, ARRAYSIZE(executable));
		const std::wstring parameters = L"--set-enforcement \"" + app.sid + L"\" " + (enabled ? L"1" : L"0") +
			(allowFilterConflict ? L" 1" : L" 0");
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
		{
			app->subtitle = CreateWindowW(L"STATIC", L"Loading account status...", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, window, nullptr, nullptr, nullptr);
			app->list = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
				0, 0, 0, 0, window, ControlId(IDC_KEYS), nullptr, nullptr);
			app->addButton = CreateWindowW(L"BUTTON", L"Add key", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_NOTIFY, 0, 0, 0, 0, window, ControlId(IDC_ADD_KEY), nullptr, nullptr);
			app->testButton = CreateWindowW(L"BUTTON", L"Test key", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_NOTIFY, 0, 0, 0, 0, window, ControlId(IDC_TEST_KEY), nullptr, nullptr);
			app->removeButton = CreateWindowW(L"BUTTON", L"Remove", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_NOTIFY, 0, 0, 0, 0, window, ControlId(IDC_REMOVE_KEY), nullptr, nullptr);
			app->enableButton = CreateWindowW(L"BUTTON", L"Enable MFA", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_NOTIFY, 0, 0, 0, 0, window, ControlId(IDC_ENABLE), nullptr, nullptr);
			app->disableButton = CreateWindowW(L"BUTTON", L"Disable MFA", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_NOTIFY, 0, 0, 0, 0, window, ControlId(IDC_DISABLE), nullptr, nullptr);
			app->refreshButton = CreateWindowW(L"BUTTON", L"Refresh", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_NOTIFY, 0, 0, 0, 0, window, ControlId(IDC_REFRESH), nullptr, nullptr);
			app->logo = LoadIconW(reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(window, GWLP_HINSTANCE)), MAKEINTRESOURCEW(IDI_APP_ICON));
			ApplyWindowFonts(*app);
			RECT client{};
			GetClientRect(window, &client);
			LayoutMainWindow(*app, client.right, client.bottom);
			Refresh(*app);
			return 0;
		}
		case WM_GETMINMAXINFO:
		{
			auto info = reinterpret_cast<MINMAXINFO*>(lParam);
			info->ptMinTrackSize.x = Scale(window, 680);
			info->ptMinTrackSize.y = Scale(window, 430);
			return 0;
		}
		case WM_SIZE:
		{
			RECT client{};
			GetClientRect(window, &client);
			LayoutMainWindow(*app, client.right, client.bottom);
			InvalidateRect(window, nullptr, TRUE);
			return 0;
		}
		case WM_DPICHANGED:
		{
			const auto suggested = reinterpret_cast<const RECT*>(lParam);
			SetWindowPos(window, nullptr, suggested->left, suggested->top,
				suggested->right - suggested->left, suggested->bottom - suggested->top,
				SWP_NOZORDER | SWP_NOACTIVATE);
			ApplyWindowFonts(*app);
			return 0;
		}
		case WM_ERASEBKGND: return 1;
		case WM_PAINT:
		{
			PAINTSTRUCT paint{};
			HDC dc = BeginPaint(window, &paint);
			RECT client{};
			GetClientRect(window, &client);
			HBRUSH background = CreateSolidBrush(RGB(247, 249, 252));
			FillRect(dc, &client, background);
			DeleteObject(background);
			RECT header{ 0, 0, client.right, Scale(window, 112) };
			HBRUSH headerBrush = CreateSolidBrush(RGB(20, 45, 78));
			FillRect(dc, &header, headerBrush);
			DeleteObject(headerBrush);
			SetBkMode(dc, TRANSPARENT);
			SetTextColor(dc, RGB(255, 255, 255));
			HFONT oldFont = reinterpret_cast<HFONT>(SelectObject(dc, app->titleFont));
			RECT titleRect{ Scale(window, 86), Scale(window, 22), client.right - Scale(window, 24), Scale(window, 58) };
			DrawTextW(dc, L"Windows FIDO Logon", -1, &titleRect, DT_SINGLELINE | DT_VCENTER);
			SelectObject(dc, oldFont);
			SetTextColor(dc, RGB(189, 212, 239));
			RECT hintRect{ Scale(window, 86), Scale(window, 62), client.right - Scale(window, 24), Scale(window, 94) };
			DrawTextW(dc, L"Password plus a USB security key, protected locally", -1, &hintRect, DT_SINGLELINE | DT_VCENTER);
			if (app->logo)
				DrawIconEx(dc, Scale(window, 24), Scale(window, 24), app->logo, Scale(window, 48), Scale(window, 48), 0, nullptr, DI_NORMAL);
			EndPaint(window, &paint);
			return 0;
		}
		case WM_CTLCOLORSTATIC:
			SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
			SetTextColor(reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam) == app->subtitle ? RGB(189, 212, 239) : RGB(74, 85, 104));
			return reinterpret_cast<LRESULT>(GetStockObject(NULL_BRUSH));
		case WM_DESTROY:
			if (app->uiFont) DeleteObject(app->uiFont);
			if (app->titleFont) DeleteObject(app->titleFont);
			if (app->logo) DestroyIcon(app->logo);
			PostQuitMessage(0); return 0;
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
		}
		return DefWindowProcW(window, message, wParam, lParam);
	}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
	int argc = 0;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argc >= 4 && argc <= 5 && _wcsicmp(argv[1], L"--set-enforcement") == 0)
	{
		localfido::BrokerClient broker;
		std::wstring error;
		const bool allowFilterConflict = argc == 5 && wcstol(argv[4], nullptr, 10) != 0;
		const bool ok = broker.SetEnforcement(argv[2], wcstol(argv[3], nullptr, 10) != 0, error, allowFilterConflict);
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
	SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
	WNDCLASSW cls{};
	cls.lpfnWndProc = MainWindow;
	cls.hInstance = instance;
	cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
	cls.hbrBackground = nullptr;
	cls.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(IDI_APP_ICON));
	cls.lpszClassName = L"WindowsFidoLogonManager";
	if (!RegisterClassW(&cls)) return 1;
	HWND window = CreateWindowExW(WS_EX_APPWINDOW, cls.lpszClassName, L"Windows FIDO Logon", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME,
		CW_USEDEFAULT, CW_USEDEFAULT, 760, 540, nullptr, nullptr, instance, &app);
	if (!window) return 1;
	ShowWindow(window, show);
	UpdateWindow(window);
	MSG message{};
	while (GetMessageW(&message, nullptr, 0, 0) > 0) { TranslateMessage(&message); DispatchMessageW(&message); }
	return static_cast<int>(message.wParam);
}
