// Exercise the actual Win32 dispatcher without contacting the installed Broker
// or changing the machine's MFA policy.
#define wWinMain ManagerEntryForTests
#include "../Manager/main.cpp"
#undef wWinMain
#include "BrokerPipeIo.h"
#include <atomic>
#include <iostream>

namespace
{
	void Require(bool condition, const char* message)
	{
		if (!condition) throw std::runtime_error(message);
	}

	int timerMessages = 0;
	bool promptOnUi = false;
	bool promptFits = false;
	void CALLBACK CancelTestPrompt(HWND owner, UINT, UINT_PTR timer, DWORD)
	{
		HWND prompt = FindWindowW(L"WindowsFidoLogonPrompt", L"Test PIN");
		if (!prompt) return;
		promptOnUi = GetWindowThreadProcessId(prompt, nullptr) == GetCurrentThreadId();
		auto state = reinterpret_cast<PromptState*>(GetWindowLongPtrW(prompt, GWLP_USERDATA));
		RECT edit{}, cancel{}, client{};
		GetWindowRect(state->edit, &edit);
		GetWindowRect(GetDlgItem(prompt, IDCANCEL), &cancel);
		GetClientRect(prompt, &client);
		MapWindowPoints(prompt, nullptr, reinterpret_cast<POINT*>(&client), 2);
		promptFits = edit.bottom < cancel.top && cancel.bottom < client.bottom && cancel.right < client.right;
		KillTimer(owner, timer);
		PostMessageW(prompt, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), reinterpret_cast<LPARAM>(GetDlgItem(prompt, IDCANCEL)));
	}
	void PumpUntil(const std::function<bool()>& done)
	{
		const ULONGLONG deadline = GetTickCount64() + 5000;
		while (!done())
		{
			Require(GetTickCount64() < deadline, "UI message loop stalled");
			MSG msg{};
			while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE))
			{
				if (msg.message == WM_TIMER) ++timerMessages;
				TranslateMessage(&msg);
				DispatchMessageW(&msg);
			}
			MsgWaitForMultipleObjects(0, nullptr, FALSE, 10, QS_ALLINPUT);
		}
	}

	void TestPipeTimeout()
	{
		const auto name = L"\\\\.\\pipe\\WflUiTest-" + std::to_wstring(GetCurrentProcessId());
		HANDLE server = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 1024, 1024, 0, nullptr);
		Require(server != INVALID_HANDLE_VALUE, "test pipe creation failed");
		HANDLE client = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
		Require(client != INVALID_HANDLE_VALUE, "test pipe connection failed");
		char buffer[16]{};
		DWORD count = 0;
		const auto started = GetTickCount64();
		const bool ok = localfido::TransferBrokerMessage(client, buffer, sizeof(buffer), count, false, 80);
		const auto error = GetLastError();
		Require(!ok && error == ERROR_SEM_TIMEOUT, "stalled Broker read was not cancelled");
		Require(GetTickCount64() - started < 2000, "Broker timeout exceeded bound");
		char sent[] = "ok";
		Require(localfido::TransferBrokerMessage(server, sent, sizeof(sent), count, true, 500), "test reply failed");
		Require(localfido::TransferBrokerMessage(client, buffer, sizeof(buffer), count, false, 500), "read after cancellation failed");
		Require(count == sizeof(sent) && buffer[0] == 'o', "pipe reply corrupted");
		CloseHandle(client);
		CloseHandle(server);
	}

	void TestFilterRecognition()
	{
		const std::wstring clsid = L"{DDC0EED2-ADBE-40B6-A217-EDE16A79A0DE}";
		Require(localfido::MatchesWindowsGenericFilter(clsid, L"credprovs.dll", L"C:\\Windows\\System32"), "built-in Filter rejected");
		Require(localfido::MatchesWindowsGenericFilter(clsid, L"\"C:\\Windows\\System32\\credprovs.dll\"", L"C:\\Windows\\System32"), "quoted built-in path rejected");
		Require(!localfido::MatchesWindowsGenericFilter(clsid, L"C:\\Temp\\credprovs.dll", L"C:\\Windows\\System32"), "non-system server accepted");
		Require(!localfido::MatchesWindowsGenericFilter(clsid, L"C:\\Windows\\System32\\thirdparty.dll", L"C:\\Windows\\System32"), "third-party system DLL accepted");
		Require(!localfido::MatchesWindowsGenericFilter(L"{other}", L"credprovs.dll", L"C:\\Windows\\System32"), "unknown Filter accepted");
	}

	void TestUi()
	{
		SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
		WNDCLASSW cls{};
		cls.lpfnWndProc = MainWindow;
		cls.hInstance = GetModuleHandleW(nullptr);
		cls.lpszClassName = L"WflManagerUiTest";
		Require(RegisterClassW(&cls) != 0, "test window registration failed");
		AppState app;
		app.username = L"Test account";
		HWND window = CreateWindowExW(0, cls.lpszClassName, L"Manager UI tests", WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
			0, 0, 900, 700, nullptr, nullptr, cls.hInstance, &app);
		Require(window != nullptr, "test window creation failed");
		MSG initial{};
		PeekMessageW(&initial, window, WM_INITIAL_REFRESH, WM_INITIAL_REFRESH, PM_REMOVE);
		app.statusLoaded = true;
		SetBusy(app, false);
		Require(!IsWindowEnabled(app.enableButton) && !IsWindowEnabled(app.disableButton), "invalid policy actions enabled");
		Require(!IsWindowEnabled(app.testButton) && !IsWindowEnabled(app.removeButton), "empty key actions enabled");
		for (int height : { 520, 560, 800 })
		{
			SetWindowPos(window, nullptr, 0, 0, Scale(window, 680), Scale(window, height), SWP_NOMOVE | SWP_NOZORDER);
			RECT list{}, button{}, progress{}, add{};
			GetWindowRect(app.list, &list);
			GetWindowRect(app.enableButton, &button);
			GetWindowRect(app.addButton, &add);
			GetWindowRect(app.progress, &progress);
			Require(list.bottom + Scale(window, 12) <= button.top, "list overlaps policy buttons");
			Require(button.bottom < add.top && add.bottom < progress.top, "button rows/progress overlap");
			Require(list.bottom - list.top >= Scale(window, 100), "key list too short at minimum size");
		}
		for (int notification : { BN_SETFOCUS, BN_KILLFOCUS, BN_DOUBLECLICKED })
		{
			SendMessageW(window, WM_COMMAND, MAKEWPARAM(IDC_REFRESH, notification), reinterpret_cast<LPARAM>(app.refreshButton));
			Require(!app.busy, "focus/double-click notification started a workflow");
		}
		SendMessageW(window, WM_COMMAND, MAKEWPARAM(IDC_REFRESH, BN_CLICKED), 0);
		Require(!app.busy, "non-control command started a workflow");
		const DWORD uiThread = GetCurrentThreadId();
		std::atomic<bool> workerStarted{ false }, releaseWorker{ false };
		bool uiCalled = false;
		SetTimer(window, 7, 10, nullptr);
		Require(StartOperation(app, [&] {
			workerStarted = GetCurrentThreadId() != uiThread;
			while (!releaseWorker.load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
			OnUi(window, [&] { uiCalled = GetCurrentThreadId() == uiThread; });
		}), "worker failed to start");
		PumpUntil([&] { return workerStarted.load() && timerMessages >= 5; });
		Require(app.busy && !IsWindowEnabled(app.refreshButton), "busy controls remain enabled");
		Require(!StartOperation(app, [] {}), "overlapping operation accepted");
		for (int index = 0; index < 20; ++index)
			SendMessageW(window, WM_COMMAND, MAKEWPARAM(IDC_DISABLE, BN_CLICKED), reinterpret_cast<LPARAM>(app.disableButton));
		releaseWorker = true;
		PumpUntil([&] { return !app.busy; });
		Require(uiCalled && IsWindowEnabled(app.refreshButton), "UI completion did not restore controls");
		bool promptAccepted = true;
		std::wstring secret;
		SetTimer(window, 8, 10, CancelTestPrompt);
		Require(StartOperation(app, [&] { promptAccepted = Prompt(window, L"Test PIN", L"Cancel this test prompt", true, secret); }), "prompt worker failed");
		PumpUntil([&] { return !app.busy; });
		Require(promptOnUi, "prompt created on worker");
		Require(promptFits, "prompt controls overlap or clip");
		Require(!promptAccepted && IsWindowEnabled(window), "cancel failed to restore owner");
		releaseWorker = false;
		Require(StartOperation(app, [&] {
			while (!releaseWorker.load()) std::this_thread::sleep_for(std::chrono::milliseconds(5));
			Progress(window, L"Late update");
		}), "close-test worker failed");
		SendMessageW(window, WM_CLOSE, 0, 0);
		Require(IsWindow(window) && app.closePending, "owner destroyed while worker uses it");
		releaseWorker = true;
		PumpUntil([&] { return !IsWindow(window); });
		Require(!app.worker.joinable(), "worker not joined on close");
	}
}

int main()
{
	try
	{
		TestPipeTimeout();
		TestFilterRecognition();
		TestUi();
		std::cout << "ManagerUiTests passed: responsive dispatch, duplicate notifications, prompt cancel, close, layout, Filter recognition, pipe timeout\n";
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << "ManagerUiTests failed: " << error.what() << '\n';
		return 1;
	}
}
