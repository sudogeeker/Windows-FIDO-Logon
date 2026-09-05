#include "LocalAccount.h"

#include <Lm.h>
#include <Sddl.h>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Netapi32.lib")

namespace
{
	std::wstring ComputerName()
	{
		wchar_t value[MAX_COMPUTERNAME_LENGTH + 1]{};
		DWORD size = ARRAYSIZE(value);
		if (!GetComputerNameW(value, &size)) return {};
		return std::wstring(value, size);
	}

	bool SidToString(PSID sid, std::wstring& value)
	{
		LPWSTR text = nullptr;
		if (!ConvertSidToStringSidW(sid, &text)) return false;
		value.assign(text);
		LocalFree(text);
		return true;
	}

	bool TokenIdentity(HANDLE token, std::wstring& username, std::wstring& sidString, DWORD* error)
	{
		DWORD size = 0;
		GetTokenInformation(token, TokenUser, nullptr, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			if (error) *error = GetLastError();
			return false;
		}
		std::vector<BYTE> data(size);
		if (!GetTokenInformation(token, TokenUser, data.data(), size, &size))
		{
			if (error) *error = GetLastError();
			return false;
		}
		auto tokenUser = reinterpret_cast<TOKEN_USER*>(data.data());
		if (!SidToString(tokenUser->User.Sid, sidString))
		{
			if (error) *error = GetLastError();
			return false;
		}
		DWORD nameSize = 0, domainSize = 0;
		SID_NAME_USE use{};
		LookupAccountSidW(nullptr, tokenUser->User.Sid, nullptr, &nameSize, nullptr, &domainSize, &use);
		std::vector<wchar_t> name(nameSize + 1), domain(domainSize + 1);
		if (!LookupAccountSidW(nullptr, tokenUser->User.Sid, name.data(), &nameSize, domain.data(), &domainSize, &use))
		{
			if (error) *error = GetLastError();
			return false;
		}
		username.assign(name.data(), nameSize);
		return true;
	}
}

bool localfido::EnumerateLocalAccounts(std::vector<LocalAccountInfo>& accounts, DWORD* error)
{
	accounts.clear();
	const std::wstring computerName = ComputerName();
	if (computerName.empty())
	{
		if (error) *error = GetLastError();
		return false;
	}
	LPUSER_INFO_1 users = nullptr;
	DWORD entriesRead = 0, totalEntries = 0, resume = 0;
	NET_API_STATUS status = NERR_Success;
	do
	{
		status = NetUserEnum(nullptr, 1, FILTER_NORMAL_ACCOUNT, reinterpret_cast<LPBYTE*>(&users),
			MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries, &resume);
		if (status != NERR_Success && status != ERROR_MORE_DATA) break;
		for (DWORD index = 0; index < entriesRead; ++index)
		{
			const auto& user = users[index];
			if (!user.usri1_name || !*user.usri1_name || (user.usri1_flags & UF_ACCOUNTDISABLE)) continue;
			LocalAccountInfo account;
		if (ResolveLocalAccount(user.usri1_name, account.username, account.computerName, account.sidString))
				accounts.push_back(std::move(account));
		}
		if (users) { NetApiBufferFree(users); users = nullptr; }
	} while (status == ERROR_MORE_DATA);
	if (users) NetApiBufferFree(users);
	if (error) *error = status;
	return status == NERR_Success && !accounts.empty();
}

bool localfido::ResolveLocalAccount(
	const std::wstring& input,
	std::wstring& username,
	std::wstring& computerName,
	std::wstring& sidString,
	DWORD* error)
{
	username.clear();
	computerName = ComputerName();
	sidString.clear();
	if (input.empty() || computerName.empty())
	{
		if (error) *error = ERROR_INVALID_PARAMETER;
		return false;
	}

	std::wstring candidate = input;
	auto slash = candidate.find(L'\\');
	if (slash != std::wstring::npos)
	{
		const auto domain = candidate.substr(0, slash);
		if (_wcsicmp(domain.c_str(), L".") != 0 && _wcsicmp(domain.c_str(), computerName.c_str()) != 0)
		{
			if (error) *error = ERROR_NO_SUCH_USER;
			return false;
		}
		candidate = candidate.substr(slash + 1);
	}
	if (candidate.find(L'@') != std::wstring::npos)
	{
		if (error) *error = ERROR_NO_SUCH_USER;
		return false;
	}

	LPUSER_INFO_0 userInfo = nullptr;
	const NET_API_STATUS userStatus = NetUserGetInfo(nullptr, candidate.c_str(), 0, reinterpret_cast<LPBYTE*>(&userInfo));
	if (userStatus != NERR_Success)
	{
		if (error) *error = userStatus;
		return false;
	}
	NetApiBufferFree(userInfo);

	const std::wstring qualified = computerName + L"\\" + candidate;
	DWORD sidSize = 0, domainSize = 0;
	SID_NAME_USE use{};
	LookupAccountNameW(nullptr, qualified.c_str(), nullptr, &sidSize, nullptr, &domainSize, &use);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		if (error) *error = GetLastError();
		return false;
	}
	std::vector<BYTE> sid(sidSize);
	std::vector<wchar_t> domain(domainSize + 1);
	if (!LookupAccountNameW(nullptr, qualified.c_str(), sid.data(), &sidSize, domain.data(), &domainSize, &use))
	{
		if (error) *error = GetLastError();
		return false;
	}
	if (_wcsicmp(domain.data(), computerName.c_str()) != 0 || use != SidTypeUser)
	{
		if (error) *error = ERROR_NO_SUCH_USER;
		return false;
	}
	username = candidate;
	if (!SidToString(reinterpret_cast<PSID>(sid.data()), sidString))
	{
		if (error) *error = GetLastError();
		return false;
	}
	if (error) *error = ERROR_SUCCESS;
	return true;
}

bool localfido::GetCurrentProcessUser(std::wstring& username, std::wstring& sidString, DWORD* error)
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
	{
		if (error) *error = GetLastError();
		return false;
	}
	const bool ok = TokenIdentity(token, username, sidString, error);
	CloseHandle(token);
	return ok;
}

bool localfido::ResolveLocalSid(const std::wstring& sidString, std::wstring& username,
	std::wstring& computerName, DWORD* error)
{
	username.clear();
	computerName = ComputerName();
	PSID sid = nullptr;
	if (computerName.empty() || !ConvertStringSidToSidW(sidString.c_str(), &sid))
	{
		if (error) *error = GetLastError();
		return false;
	}
	DWORD nameLength = 0, domainLength = 0;
	SID_NAME_USE use{};
	LookupAccountSidW(nullptr, sid, nullptr, &nameLength, nullptr, &domainLength, &use);
	std::vector<wchar_t> name(nameLength + 1), domain(domainLength + 1);
	const BOOL found = LookupAccountSidW(nullptr, sid, name.data(), &nameLength, domain.data(), &domainLength, &use);
	const DWORD lookupError = found ? ERROR_SUCCESS : GetLastError();
	LocalFree(sid);
	if (!found || use != SidTypeUser || _wcsicmp(domain.data(), computerName.c_str()) != 0)
	{
		if (error) *error = found ? ERROR_NO_SUCH_USER : lookupError;
		return false;
	}
	username.assign(name.data(), nameLength);
	if (error) *error = ERROR_SUCCESS;
	return true;
}

bool localfido::IsCurrentProcessElevated()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
	TOKEN_ELEVATION elevation{};
	DWORD size = sizeof(elevation);
	const bool elevated = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) && elevation.TokenIsElevated;
	CloseHandle(token);
	return elevated;
}

bool localfido::IsLocalSystemSid(const std::wstring& sidString)
{
	return _wcsicmp(sidString.c_str(), L"S-1-5-18") == 0;
}

bool localfido::ValidateLocalPassword(const std::wstring& username, const std::wstring& password, DWORD* error)
{
	HANDLE token = nullptr;
	const std::wstring computerName = ComputerName();
	const BOOL ok = LogonUserW(
		username.c_str(), computerName.c_str(), password.c_str(),
		LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT, &token);
	const DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();
	if (token) CloseHandle(token);
	if (error) *error = lastError;
	return ok == TRUE;
}
