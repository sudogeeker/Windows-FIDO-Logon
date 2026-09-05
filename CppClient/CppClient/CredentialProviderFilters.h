#pragma once

#include <Windows.h>
#include <string>
#include <vector>

namespace localfido
{
	inline constexpr wchar_t kOurFilterClsid[] = L"{54B25B17-C7AE-4C2B-B3C4-E3B29A73D9B1}";
	inline constexpr wchar_t kFilterRegistry[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters";

	inline std::wstring NormalizeFilterPath(const std::wstring& raw)
	{
		const DWORD size = ExpandEnvironmentStringsW(raw.c_str(), nullptr, 0);
		if (!size) return {};
		std::vector<wchar_t> expanded(size);
		if (!ExpandEnvironmentStringsW(raw.c_str(), expanded.data(), size)) return {};
		std::wstring path(expanded.data());
		if (path.size() >= 2 && path.front() == L'"' && path.back() == L'"')
			path = path.substr(1, path.size() - 2);
		std::vector<wchar_t> full(32768);
		const DWORD length = GetFullPathNameW(path.c_str(), static_cast<DWORD>(full.size()), full.data(), nullptr);
		return length && length < full.size() ? std::wstring(full.data(), length) : std::wstring{};
	}

	inline bool MatchesWindowsGenericFilter(const std::wstring& clsid, const std::wstring& server, const std::wstring& systemDirectory)
	{
		// Recognize the built-in registration, without loading DLLs or checking certificates.
		if (_wcsicmp(clsid.c_str(), L"{DDC0EED2-ADBE-40B6-A217-EDE16A79A0DE}") != 0) return false;
		std::wstring candidate = server;
		if (_wcsicmp(candidate.c_str(), L"credprovs.dll") == 0) candidate = systemDirectory + L"\\" + candidate;
		candidate = NormalizeFilterPath(candidate);
		const auto expected = NormalizeFilterPath(systemDirectory + L"\\credprovs.dll");
		return !candidate.empty() && !expected.empty() && _wcsicmp(candidate.c_str(), expected.c_str()) == 0;
	}

	inline bool IsWindowsGenericFilter(const std::wstring& clsid)
	{
		wchar_t systemDirectory[MAX_PATH]{};
		const UINT length = GetSystemDirectoryW(systemDirectory, ARRAYSIZE(systemDirectory));
		if (!length || length >= ARRAYSIZE(systemDirectory)) return false;
		const std::wstring key = L"SOFTWARE\\Classes\\CLSID\\" + clsid + L"\\InprocServer32";
		wchar_t server[32768]{};
		DWORD bytes = sizeof(server);
		if (RegGetValueW(HKEY_LOCAL_MACHINE, key.c_str(), nullptr,
			RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY,
			nullptr, server, &bytes) != ERROR_SUCCESS) return false;
		return MatchesWindowsGenericFilter(clsid, server, systemDirectory);
	}
}
