/*
 * Copyright 2019 NetKnights GmbH
 * Licensed under the Apache License, Version 2.0.
 */
#include "RegistryReader.h"

#include <Windows.h>
#include <cwchar>
#include <utility>
#include <vector>

namespace
{
	struct ScopedHKEY
	{
		HKEY value = nullptr;
		~ScopedHKEY() { if (value) RegCloseKey(value); }
		HKEY* operator&() { return &value; }
		operator HKEY() const { return value; }
	};
}

RegistryReader::RegistryReader(const std::wstring& pathToKey) noexcept : path(pathToKey) {}

std::wstring RegistryReader::GetWString(std::wstring name) noexcept
{
	ScopedHKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
		return L"";

	DWORD type = 0;
	DWORD size = 0;
	LONG status = RegQueryValueExW(key, name.c_str(), nullptr, &type, nullptr, &size);
	if (status != ERROR_SUCCESS || type != REG_SZ || size < sizeof(wchar_t)) return L"";

	std::vector<wchar_t> value(size / sizeof(wchar_t) + 1, L'\0');
	status = RegQueryValueExW(key, name.c_str(), nullptr, &type,
		reinterpret_cast<BYTE*>(value.data()), &size);
	if (status != ERROR_SUCCESS || type != REG_SZ) return L"";
	value.back() = L'\0';
	return value.data();
}

bool RegistryReader::GetBool(std::wstring name) noexcept
{
	ScopedHKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
		return false;
	DWORD type = 0;
	DWORD size = 0;
	if (RegQueryValueExW(key, name.c_str(), nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
		return false;
	if (type == REG_DWORD && size == sizeof(DWORD))
	{
		DWORD value = 0;
		return RegQueryValueExW(key, name.c_str(), nullptr, &type,
			reinterpret_cast<BYTE*>(&value), &size) == ERROR_SUCCESS && value != 0;
	}
	return GetWString(std::move(name)) == L"1";
}

std::vector<std::wstring> RegistryReader::GetMultiSZ(const std::wstring& valueName) noexcept
{
	ScopedHKEY key;
	if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS)
		return {};

	DWORD type = 0;
	DWORD size = 0;
	LONG status = RegQueryValueExW(key, valueName.c_str(), nullptr, &type, nullptr, &size);
	if (status != ERROR_SUCCESS || type != REG_MULTI_SZ || size < sizeof(wchar_t)) return {};

	std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 2, L'\0');
	status = RegQueryValueExW(key, valueName.c_str(), nullptr, &type,
		reinterpret_cast<BYTE*>(buffer.data()), &size);
	if (status != ERROR_SUCCESS || type != REG_MULTI_SZ) return {};

	std::vector<std::wstring> result;
	for (const wchar_t* cursor = buffer.data(); *cursor; cursor += wcslen(cursor) + 1)
		result.emplace_back(cursor);
	return result;
}
