#pragma once
#include <Windows.h>

namespace localfido
{
	inline bool TransferBrokerMessage(HANDLE pipe, void* buffer, DWORD bytes, DWORD& transferred,
		bool write, DWORD timeoutMs = 15000)
	{
		OVERLAPPED operation{};
		operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!operation.hEvent) return false;
		BOOL ok = write ? WriteFile(pipe, buffer, bytes, &transferred, &operation) :
			ReadFile(pipe, buffer, bytes, &transferred, &operation);
		DWORD error = ok ? ERROR_SUCCESS : GetLastError();
		if (!ok && error == ERROR_IO_PENDING)
		{
			const DWORD wait = WaitForSingleObject(operation.hEvent, timeoutMs);
			if (wait == WAIT_OBJECT_0)
			{
				ok = GetOverlappedResult(pipe, &operation, &transferred, FALSE);
				error = ok ? ERROR_SUCCESS : GetLastError();
			}
			else
			{
				error = wait == WAIT_TIMEOUT ? ERROR_SEM_TIMEOUT : GetLastError();
				CancelIoEx(pipe, &operation);
				// Drain cancellation before the stack OVERLAPPED and buffer are released.
				DWORD ignored = 0;
				GetOverlappedResult(pipe, &operation, &ignored, TRUE);
			}
		}
		CloseHandle(operation.hEvent);
		SetLastError(error);
		return ok == TRUE;
	}
}
