#include "BrokerService.h"
#include "LocalFidoTypes.h"

#include <Windows.h>
#include <string>

namespace
{
	SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
	SERVICE_STATUS g_status{};
	HANDLE g_stopEvent = nullptr;

	void SetState(DWORD state, DWORD error = NO_ERROR)
	{
		g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
		g_status.dwCurrentState = state;
		g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
		g_status.dwWin32ExitCode = error;
		g_status.dwCheckPoint = 0;
		g_status.dwWaitHint = 0;
		if (g_statusHandle) SetServiceStatus(g_statusHandle, &g_status);
	}

	DWORD WINAPI ControlHandler(DWORD control, DWORD, void*, void*)
	{
		if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN)
		{
			SetState(SERVICE_STOP_PENDING);
			SetEvent(g_stopEvent);
			// Wake the blocking ConnectNamedPipe call so the service can stop promptly.
			HANDLE wake = CreateFileW(localfido::kBrokerPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
			if (wake != INVALID_HANDLE_VALUE) CloseHandle(wake);
		}
		return NO_ERROR;
	}

	void WINAPI ServiceMain(DWORD, LPWSTR*)
	{
		g_statusHandle = RegisterServiceCtrlHandlerExW(localfido::kServiceName, ControlHandler, nullptr);
		if (!g_statusHandle) return;
		g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!g_stopEvent) { SetState(SERVICE_STOPPED, GetLastError()); return; }
		SetState(SERVICE_RUNNING);
		BrokerService service;
		service.Run(g_stopEvent);
		CloseHandle(g_stopEvent);
		g_stopEvent = nullptr;
		SetState(SERVICE_STOPPED);
	}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc == 2 && _wcsicmp(argv[1], L"--console") == 0)
	{
		HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		BrokerService service;
		service.Run(stop);
		CloseHandle(stop);
		return 0;
	}
	SERVICE_TABLE_ENTRYW table[] = {
		{ const_cast<LPWSTR>(localfido::kServiceName), ServiceMain },
		{ nullptr, nullptr }
	};
	return StartServiceCtrlDispatcherW(table) ? 0 : static_cast<int>(GetLastError());
}
