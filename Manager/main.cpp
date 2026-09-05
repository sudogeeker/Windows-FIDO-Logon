#include "BrokerClient.h"
#include "Convert.h"
#include "CredentialProviderFilters.h"
#include "FIDODevice.h"
#include "FIDOException.h"
#include "FIDORegistrationRequest.h"
#include "LocalAccount.h"

#include <Windows.h>
#include <algorithm>
#include <functional>
#include <memory>
#include <thread>
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
	constexpr UINT WM_UI_CALL = WM_APP + 1;
	constexpr UINT WM_OPERATION_DONE = WM_APP + 2;
	constexpr UINT WM_INITIAL_REFRESH = WM_APP + 3;
	void Progress(HWND window, const std::wstring& text);

	// All HWND mutations and dialogs run on the window's thread. The worker waits
	// here only for user interaction; broker/USB I/O never runs on the UI thread.
	void OnUi(HWND window, const std::function<void()>& action)
	{
		if (GetCurrentThreadId() == GetWindowThreadProcessId(window, nullptr)) action();
		else SendMessageW(window, WM_UI_CALL, 0, reinterpret_cast<LPARAM>(&action));
	}

	int ShowMessage(HWND owner, const std::wstring& text, const std::wstring& title, UINT flags)
	{
		int result = IDCANCEL;
		OnUi(owner, [&] { result = MessageBoxW(owner, text.c_str(), title.c_str(), flags); });
		return result;
	}
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
		const LONG opened = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kFilterRegistry, 0, KEY_READ | KEY_WOW64_64KEY, &key);
		if (opened == ERROR_FILE_NOT_FOUND) return std::nullopt;
		if (opened != ERROR_SUCCESS) throw std::runtime_error("Unable to inspect installed Credential Provider Filters.");
		for (DWORD index = 0;; ++index)
		{
			wchar_t name[128]{};
			DWORD length = ARRAYSIZE(name);
			const LONG status = RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
			if (status == ERROR_NO_MORE_ITEMS) break;
			if (status != ERROR_SUCCESS) { RegCloseKey(key); throw std::runtime_error("Unable to enumerate Credential Provider Filters."); }
			if (_wcsicmp(name, kOurFilterGuid) == 0 || localfido::IsWindowsGenericFilter(name)) continue;
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
		HFONT font = nullptr;
		int messageHeight = 0;
		bool scrollMessage = false;
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
			const int margin = Scale(window, 16), width = Scale(window, 420);
			const int editTop = margin + state->messageHeight + Scale(window, 12);
			const int buttonsTop = editTop + Scale(window, 42);
			HWND label = CreateWindowW(state->scrollMessage ? L"EDIT" : L"STATIC", state->message.c_str(), WS_CHILD | WS_VISIBLE |
				(state->scrollMessage ? ES_READONLY | ES_MULTILINE | WS_VSCROLL : 0), margin, margin, width, state->messageHeight, window, nullptr, nullptr, nullptr);
			state->edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP |
				ES_AUTOHSCROLL | (state->password ? ES_PASSWORD : 0), margin, editTop, width, Scale(window, 28), window, nullptr, nullptr, nullptr);
			HWND ok = CreateWindowW(L"BUTTON", L"OK", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON, Scale(window, 270), buttonsTop, Scale(window, 78), Scale(window, 30),
				window, ControlId(IDOK), nullptr, nullptr);
			HWND cancel = CreateWindowW(L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | WS_TABSTOP, Scale(window, 358), buttonsTop, Scale(window, 78), Scale(window, 30),
				window, ControlId(IDCANCEL), nullptr, nullptr);
			for (HWND control : { label, state->edit, ok, cancel })
				SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(state->font), FALSE);
			return 0;
		}
		case WM_COMMAND:
			if (HIWORD(wParam) != BN_CLICKED) return 0;
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
		if (GetCurrentThreadId() != GetWindowThreadProcessId(owner, nullptr))
		{
			bool accepted = false;
			OnUi(owner, [&] { accepted = Prompt(owner, title, message, password, value); });
			return accepted;
		}
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
		state.font = CreateFontW(-MulDiv(10, DpiFor(owner), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
			DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
		HDC dc = GetDC(owner);
		HGDIOBJ oldFont = SelectObject(dc, state.font);
		RECT measured{ 0, 0, Scale(owner, 420), 0 };
		DrawTextW(dc, message.c_str(), -1, &measured, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
		SelectObject(dc, oldFont);
		ReleaseDC(owner, dc);
		MONITORINFO monitor{ sizeof(monitor) };
		GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &monitor);
		const int maximumHeight = std::max<int>(Scale(owner, 44), monitor.rcWork.bottom - monitor.rcWork.top - Scale(owner, 180));
		state.messageHeight = std::min(std::max<int>(Scale(owner, 44), measured.bottom), maximumHeight);
		state.scrollMessage = measured.bottom > state.messageHeight;
		const DWORD style = WS_POPUP | WS_CAPTION | WS_SYSMENU;
		RECT frame{ 0, 0, Scale(owner, 452), state.messageHeight + Scale(owner, 116) };
		AdjustWindowRectExForDpi(&frame, style, FALSE, WS_EX_DLGMODALFRAME, DpiFor(owner));
		RECT ownerRect{};
		GetWindowRect(owner, &ownerRect);
		const int width = frame.right - frame.left, height = frame.bottom - frame.top;
		const int x = std::max(monitor.rcWork.left, std::min((ownerRect.left + ownerRect.right - width) / 2, monitor.rcWork.right - width));
		const int y = std::max(monitor.rcWork.top, std::min((ownerRect.top + ownerRect.bottom - height) / 2, monitor.rcWork.bottom - height));
		EnableWindow(owner, FALSE);
		HWND dialog = CreateWindowExW(WS_EX_DLGMODALFRAME, L"WindowsFidoLogonPrompt", title.c_str(),
			style, x, y, width, height, owner, nullptr,
			GetModuleHandleW(nullptr), &state);
		if (!dialog) { DeleteObject(state.font); EnableWindow(owner, TRUE); return false; }
		ShowWindow(dialog, SW_SHOW);
		SetFocus(state.edit);
		MSG msg{};
		BOOL received = TRUE;
		while (IsWindow(dialog) && (received = GetMessageW(&msg, nullptr, 0, 0)) > 0)
		{
			if (!IsDialogMessageW(dialog, &msg)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
		}
		if (IsWindow(dialog)) DestroyWindow(dialog);
		if (received == 0) PostQuitMessage(static_cast<int>(msg.wParam));
		DeleteObject(state.font);
		EnableWindow(owner, TRUE);
		SetForegroundWindow(owner);
		if (state.accepted) value = std::move(state.value);
		return state.accepted;
	}

	void Error(HWND owner, const std::wstring& text)
	{
		if (!owner) MessageBoxW(nullptr, text.c_str(), L"Windows FIDO Logon", MB_OK | MB_ICONERROR);
		else ShowMessage(owner, text, L"Windows FIDO Logon", MB_OK | MB_ICONERROR);
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
		Progress(owner, L"Touch your security key to continue...");
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
		HWND progress = nullptr;
		std::wstring username;
		std::wstring sid;
		localfido::AccountStatus status;
		HFONT uiFont = nullptr;
		HFONT titleFont = nullptr;
		bool busy = false;
		bool statusLoaded = false;
		bool closePending = false;
		std::thread worker;
	};

	struct Operation
	{
		AppState& ui;
		HWND window;
		std::wstring username, sid;
		localfido::AccountStatus status;
		localfido::BrokerClient broker;
		LRESULT selectedItem;
		explicit Operation(AppState& app) : ui(app), window(app.window), username(app.username), sid(app.sid),
			status(app.status), selectedItem(SendMessageW(app.list, LB_GETCURSEL, 0, 0)) {}
	};

	void Progress(HWND window, const std::wstring& text)
	{
		OnUi(window, [&] {
			auto app = reinterpret_cast<AppState*>(GetWindowLongPtrW(window, GWLP_USERDATA));
			SetWindowTextW(app->progress, text.c_str());
		});
	}

	void SetBusy(AppState& app, bool busy)
	{
		app.busy = busy;
		EnableWindow(app.addButton, !busy && app.statusLoaded);
		EnableWindow(app.testButton, !busy && app.statusLoaded && !app.status.credentials.empty());
		EnableWindow(app.removeButton, !busy && app.statusLoaded && SendMessageW(app.list, LB_GETCURSEL, 0, 0) != LB_ERR);
		EnableWindow(app.enableButton, !busy && app.statusLoaded && !app.status.enforced && !app.status.credentials.empty());
		EnableWindow(app.disableButton, !busy && app.statusLoaded && app.status.enforced);
		EnableWindow(app.refreshButton, !busy);
	}

	bool StartOperation(AppState& app, const std::function<void()>& work)
	{
		if (app.busy || app.closePending) return false;
		SetBusy(app, true);
		SetWindowTextW(app.progress, L"Working...");
		try
		{
			app.worker = std::thread([window = app.window, work] {
				try { work(); }
				catch (const std::exception& exception) { Error(window, Convert::ToWString(exception.what())); }
				catch (...) { Error(window, L"The operation could not be completed."); }
				PostMessageW(window, WM_OPERATION_DONE, 0, 0);
			});
		}
		catch (...)
		{
			SetBusy(app, false);
			SetWindowTextW(app.progress, L"Unable to start operation.");
			return false;
		}
		return true;
	}

	void SetControlFont(HWND control, HFONT font)
	{
		if (control && font) SendMessageW(control, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
	}

	void LayoutMainWindow(AppState& app, int width, int height)
	{
		const int margin = Scale(app.window, 24);
		const int headerHeight = Scale(app.window, 136);
		const int gap = Scale(app.window, 12);
		const int buttonHeight = Scale(app.window, 38);
		const int listTop = headerHeight + Scale(app.window, 26);
		const int contentWidth = (width - margin * 2);

		const int buttonTop = height - margin - Scale(app.window, 28) - buttonHeight;
		const int buttonWidth = (contentWidth - gap * 2) / 3;
		const int secondRowTop = buttonTop - gap - buttonHeight;
		struct Placement { HWND control; int x, y, width, height; };
		const Placement placements[] = {
			{ app.addButton, margin, buttonTop, buttonWidth, buttonHeight },
			{ app.testButton, margin + buttonWidth + gap, buttonTop, buttonWidth, buttonHeight },
			{ app.removeButton, margin + (buttonWidth + gap) * 2, buttonTop, buttonWidth, buttonHeight },
			{ app.list, margin, listTop, contentWidth, std::max(0, secondRowTop - gap - listTop) },
			{ app.enableButton, margin, secondRowTop, buttonWidth, buttonHeight },
			{ app.disableButton, margin + buttonWidth + gap, secondRowTop, buttonWidth, buttonHeight },
			{ app.refreshButton, margin + (buttonWidth + gap) * 2, secondRowTop, buttonWidth, buttonHeight },
			{ app.subtitle, margin, headerHeight - Scale(app.window, 30), contentWidth, Scale(app.window, 22) },
			{ app.progress, margin, height - margin - Scale(app.window, 20), contentWidth, Scale(app.window, 20) }
		};

		HDWP deferred = BeginDeferWindowPos(ARRAYSIZE(placements));
		for (const auto& placement : placements)
		{
			if (!deferred) break;
			deferred = DeferWindowPos(deferred, placement.control, nullptr, placement.x, placement.y,
				placement.width, placement.height, SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOCOPYBITS);
		}
		const bool positioned = deferred && EndDeferWindowPos(deferred);
		if (!positioned)
		{
			for (const auto& placement : placements)
				SetWindowPos(placement.control, nullptr, placement.x, placement.y, placement.width, placement.height,
					SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOCOPYBITS);
		}
		RedrawWindow(app.window, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
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
		for (HWND control : { app.list, app.subtitle, app.progress, app.addButton, app.testButton, app.removeButton, app.enableButton, app.disableButton, app.refreshButton })
			SetControlFont(control, app.uiFont);
	}

	bool Refresh(Operation& app)
	{
		Progress(app.window, L"Reading account status...");
		std::wstring error;
		if (!app.broker.GetStatus(app.sid, app.status, error))
		{
			OnUi(app.window, [&] { app.ui.statusLoaded = false; SetWindowTextW(app.ui.subtitle, L"Account status unavailable"); });
			Error(app.window, error); return false;
		}
		OnUi(app.window, [&] {
			app.ui.status = app.status;
			app.ui.statusLoaded = true;
			SendMessageW(app.ui.list, LB_RESETCONTENT, 0, 0);
			for (const auto& item : app.status.credentials)
			{
				std::wstring line = Convert::ToWString(item.label) + L"  [" + Convert::ToWString(item.aaguid) + L"]";
				SendMessageW(app.ui.list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(line.c_str()));
			}
			const std::wstring summary = L"Signed in as " + app.username + L"  |  " +
				std::to_wstring(app.status.credentials.size()) + (app.status.credentials.size() == 1 ? L" registered key" : L" registered keys") +
				(app.status.enforced ? L"  |  MFA enabled" : L"  |  MFA disabled");
			SetWindowTextW(app.ui.subtitle, summary.c_str());
			SetWindowTextW(app.window, L"Windows FIDO Logon");
			InvalidateRect(app.window, nullptr, TRUE);
		});
		return true;
	}

	bool AddKey(Operation& app)
	{
		std::wstring password, label;
		if (!Prompt(app.window, L"Authorize enrollment", L"Enter your current Windows password:", true, password)) return false;
		if (!Prompt(app.window, L"Name security key", L"Enter a label for this security key:", false, label)) { ClearSecret(password); return false; }
		localfido::AuthenticationChallenge authorization;
		localfido::RegistrationChallenge registration;
		std::wstring error;
		Progress(app.window, L"Authorizing enrollment...");
		if (!app.broker.BeginRegistration(app.sid, app.username, password, Convert::ToString(label), authorization, registration, error))
		{
			ClearSecret(password); Error(app.window, error); return false;
		}
		ClearSecret(password);
		if (authorization.enforced)
		{
			Progress(app.window, L"Finding registered USB security keys...");
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

		Progress(app.window, L"Finding USB security keys...");
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
			Progress(app.window, L"Touch the new security key to register it...");
			auto created = device.Register(request, registration.origin, pin);
			if (!created) throw std::runtime_error("The authenticator did not return a credential.");
			localfido::AuthenticationChallenge proof;
			if (!app.broker.CommitRegistration(registration.sessionId, Convert::ToString(label), created->attestationObject,
				created->clientDataJSON, proof, error)) throw std::runtime_error(Convert::ToString(error));
			FIDOSignResponse proofAssertion;
			if (!SignChallenge(app.window, proof, device, pin, proofAssertion))
			{
				if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
				return false;
			}
			if (!app.broker.FinishRegistration(proof.sessionId, proofAssertion, error)) throw std::runtime_error(Convert::ToString(error));
		}
		catch (const std::exception& exception)
		{
			if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
			Error(app.window, Convert::ToWString(exception.what()));
			return false;
		}
		if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
		ShowMessage(app.window, L"Security key registered and proof of possession verified.", L"Windows FIDO Logon", MB_OK | MB_ICONINFORMATION);
		return Refresh(app);
	}

	bool TestKey(Operation& app)
	{
		localfido::AuthenticationChallenge challenge;
		std::wstring error;
		if (!app.broker.BeginTest(app.sid, challenge, error)) { Error(app.window, error); return false; }
		Progress(app.window, L"Finding registered USB security keys...");
		auto devices = FIDODevice::GetDevices();
		auto selected = ChooseDevice(app.window, devices, L"Choose a registered key to test.");
		if (!selected) return false;
		std::string pin;
		FIDOSignResponse assertion;
		const bool signedOk = SignChallenge(app.window, challenge, devices[*selected], pin, assertion);
		if (!pin.empty()) SecureZeroMemory(pin.data(), pin.size());
		if (!signedOk) return false;
		if (!app.broker.FinishAuthentication(challenge.sessionId, assertion, error)) { Error(app.window, error); return false; }
		ShowMessage(app.window, L"The security key is registered and valid.", L"Windows FIDO Logon", MB_OK | MB_ICONINFORMATION);
		return Refresh(app);
	}

	bool RemoveKey(Operation& app)
	{
		const LRESULT selectedItem = app.selectedItem;
		if (selectedItem == LB_ERR || static_cast<size_t>(selectedItem) >= app.status.credentials.size())
		{
			Error(app.window, L"Select a security key to remove."); return false;
		}
		std::wstring password;
		if (!Prompt(app.window, L"Authorize removal", L"Enter your current Windows password:", true, password)) return false;
		std::wstring error;
		if (!app.broker.RemoveCredentialWithPassword(app.sid, app.username, password,
			app.status.credentials[static_cast<size_t>(selectedItem)].credentialId, error))
		{
			ClearSecret(password); Error(app.window, error); return false;
		}
		ClearSecret(password);
		return Refresh(app);
	}

	void ChangePolicy(Operation& app, bool enabled)
	{
		if (!Refresh(app) || app.status.enforced == enabled) return;
		if (enabled && app.status.credentials.empty())
		{
			Error(app.window, L"Register at least one security key before enabling MFA.");
			return;
		}
		bool allowFilterConflict = false;
		if (enabled && app.status.credentials.size() == 1)
		{
			const int answer = ShowMessage(app.window,
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
				if (ShowMessage(app.window, warning, L"Credential Provider Filter conflict", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES)
					return;
				allowFilterConflict = true;
			}
		}
		std::wstring password;
		if (!Prompt(app.window, enabled ? L"Authorize MFA enablement" : L"Authorize MFA disablement",
			L"Enter your current Windows password:", true, password)) return;
		Progress(app.window, enabled ? L"Enabling MFA..." : L"Disabling MFA...");
		std::wstring error;
		const bool changed = app.broker.SetEnforcement(app.sid, app.username, password, enabled, error, allowFilterConflict);
		ClearSecret(password);
		if (!changed) { Error(app.window, error); return; }
		Refresh(app);
	}

	void DispatchCommand(AppState& app, int id)
	{
		if (app.busy || app.closePending) return;
		HWND button = GetDlgItem(app.window, id);
		if (!button || !IsWindowEnabled(button)) return;
		auto operation = std::make_shared<Operation>(app);
		StartOperation(app, [operation, id] {
			switch (id)
			{
			case IDC_ADD_KEY: AddKey(*operation); break;
			case IDC_TEST_KEY: TestKey(*operation); break;
			case IDC_REMOVE_KEY: RemoveKey(*operation); break;
			case IDC_ENABLE: ChangePolicy(*operation, true); break;
			case IDC_DISABLE: ChangePolicy(*operation, false); break;
			case IDC_REFRESH: Refresh(*operation); break;
			}
		});
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
		case WM_UI_CALL:
			if (!app->closePending) (*reinterpret_cast<const std::function<void()>*>(lParam))();
			return 0;
		case WM_OPERATION_DONE:
			if (app->worker.joinable()) app->worker.join();
			SetBusy(*app, false);
			SetWindowTextW(app->progress, L"");
			if (app->closePending) DestroyWindow(window);
			return 0;
		case WM_INITIAL_REFRESH:
			DispatchCommand(*app, IDC_REFRESH);
			return 0;
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
			app->progress = CreateWindowW(L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_ENDELLIPSIS, 0, 0, 0, 0, window, nullptr, nullptr, nullptr);
			ApplyWindowFonts(*app);
			RECT client{};
			GetClientRect(window, &client);
			LayoutMainWindow(*app, client.right, client.bottom);
			SetBusy(*app, false);
			PostMessageW(window, WM_INITIAL_REFRESH, 0, 0);
			return 0;
		}
		case WM_GETMINMAXINFO:
		{
			auto info = reinterpret_cast<MINMAXINFO*>(lParam);
			info->ptMinTrackSize.x = Scale(window, 680);
			info->ptMinTrackSize.y = Scale(window, 520);
			return 0;
		}
		case WM_SIZE:
		{
			RECT client{};
			GetClientRect(window, &client);
			LayoutMainWindow(*app, client.right, client.bottom);
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
			RECT header{ 0, 0, client.right, Scale(window, 136) };
			HBRUSH headerBrush = CreateSolidBrush(RGB(20, 45, 78));
			FillRect(dc, &header, headerBrush);
			DeleteObject(headerBrush);
			SetBkMode(dc, TRANSPARENT);
			SetTextColor(dc, RGB(255, 255, 255));
			HFONT oldFont = reinterpret_cast<HFONT>(SelectObject(dc, app->titleFont));
			RECT titleRect{ Scale(window, 24), Scale(window, 18), client.right - Scale(window, 24), Scale(window, 52) };
			DrawTextW(dc, L"Windows FIDO Logon", -1, &titleRect, DT_SINGLELINE | DT_VCENTER);
			SelectObject(dc, app->uiFont);
			SetTextColor(dc, RGB(189, 212, 239));
			RECT hintRect{ Scale(window, 24), Scale(window, 54), client.right - Scale(window, 24), Scale(window, 82) };
			DrawTextW(dc, L"Password plus a USB security key, protected locally", -1, &hintRect, DT_SINGLELINE | DT_VCENTER);
			SelectObject(dc, oldFont);
			EndPaint(window, &paint);
			return 0;
		}
		case WM_CTLCOLORSTATIC:
			SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
			SetTextColor(reinterpret_cast<HDC>(wParam), reinterpret_cast<HWND>(lParam) == app->subtitle ? RGB(189, 212, 239) : RGB(74, 85, 104));
			{
				const bool header = reinterpret_cast<HWND>(lParam) == app->subtitle;
				SetDCBrushColor(reinterpret_cast<HDC>(wParam), header ? RGB(20, 45, 78) : RGB(247, 249, 252));
				return reinterpret_cast<LRESULT>(GetStockObject(DC_BRUSH));
			}
		case WM_CLOSE:
			if (app->busy)
			{
				app->closePending = true;
				SetWindowTextW(app->progress, L"Closing after the current operation finishes...");
				return 0;
			}
			DestroyWindow(window);
			return 0;
		case WM_DESTROY:
			if (app->uiFont) DeleteObject(app->uiFont);
			if (app->titleFont) DeleteObject(app->titleFont);
			PostQuitMessage(0); return 0;
		case WM_COMMAND:
			if (LOWORD(wParam) == IDC_KEYS && HIWORD(wParam) == LBN_SELCHANGE)
			{
				SetBusy(*app, app->busy);
				return 0;
			}
			// BS_NOTIFY also sends focus/double-click notifications. Only a real
			// click from the expected button may start a workflow.
			if (HIWORD(wParam) != BN_CLICKED || !lParam ||
				reinterpret_cast<HWND>(lParam) != GetDlgItem(window, LOWORD(wParam))) return 0;
			DispatchCommand(*app, LOWORD(wParam));
			return 0;
		}
		return DefWindowProcW(window, message, wParam, lParam);
	}
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int show)
{
	if (!localfido::IsCurrentProcessElevated())
	{
		Error(nullptr, L"Windows FIDO Logon Manager must be run as administrator.");
		return 1;
	}

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
	HWND window = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_CONTROLPARENT, cls.lpszClassName, L"Windows FIDO Logon",
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_THICKFRAME | WS_CLIPCHILDREN,
		CW_USEDEFAULT, CW_USEDEFAULT, MulDiv(760, GetDpiForSystem(), 96), MulDiv(560, GetDpiForSystem(), 96), nullptr, nullptr, instance, &app);
	if (!window) return 1;
	ShowWindow(window, show);
	UpdateWindow(window);
	MSG message{};
	while (GetMessageW(&message, nullptr, 0, 0) > 0)
	{
		if (!IsDialogMessageW(window, &message)) { TranslateMessage(&message); DispatchMessageW(&message); }
	}
	return static_cast<int>(message.wParam);
}
