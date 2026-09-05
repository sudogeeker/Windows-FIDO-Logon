#pragma once

#include <Windows.h>
#include <string>

namespace localfido
{
	bool ResolveLocalAccount(
		const std::wstring& input,
		std::wstring& username,
		std::wstring& computerName,
		std::wstring& sidString,
		DWORD* error = nullptr);
	bool ResolveLocalSid(const std::wstring& sidString, std::wstring& username,
		std::wstring& computerName, DWORD* error = nullptr);

	bool GetCurrentProcessUser(std::wstring& username, std::wstring& sidString, DWORD* error = nullptr);
	bool IsCurrentProcessElevated();
	bool IsLocalSystemSid(const std::wstring& sidString);
	bool ValidateLocalPassword(const std::wstring& username, const std::wstring& password, DWORD* error = nullptr);
}
