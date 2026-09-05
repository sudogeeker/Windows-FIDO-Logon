#include "LocalCredentialStore.h"

#include "Convert.h"
#include "LocalAccount.h"
#include "RegistryReader.h"

#include <Windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <nlohmann/json.hpp>
#include <sddl.h>
#include <shlobj.h>
#include <algorithm>
#include <cctype>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <set>
#include <sstream>
#include <utility>

#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Shell32.lib")

using json = nlohmann::json;

namespace
{
	std::string GenerateHexId()
	{
		BYTE bytes[16]{};
		if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
		std::ostringstream stream;
		stream << std::hex << std::setfill('0');
		for (BYTE value : bytes) stream << std::setw(2) << static_cast<unsigned int>(value);
		return stream.str();
	}

	json CredentialToJson(const localfido::CredentialRecord& value)
	{
		return {
			{"credentialId", value.credentialId},
			{"cosePublicKey", value.cosePublicKey},
			{"algorithm", value.algorithm},
			{"aaguid", value.aaguid},
			{"label", value.label},
			{"createdAt", value.createdAt},
			{"signCount", value.signCount}
		};
	}

	localfido::CredentialRecord CredentialFromJson(const json& value)
	{
		localfido::CredentialRecord result;
		result.credentialId = value.at("credentialId").get<std::string>();
		result.cosePublicKey = value.at("cosePublicKey").get<std::string>();
		result.algorithm = value.value("algorithm", localfido::kEs256Algorithm);
		result.aaguid = value.value("aaguid", "");
		result.label = value.value("label", "Security key");
		result.createdAt = value.value("createdAt", "");
		result.signCount = value.value("signCount", 0u);
		return result;
	}

	json VaultToJson(const localfido::Vault& vault)
	{
		json accounts = json::array();
		for (const auto& account : vault.accounts)
		{
			json credentials = json::array();
			for (const auto& credential : account.credentials) credentials.push_back(CredentialToJson(credential));
			accounts.push_back({
				{"sid", Convert::ToString(account.sid)},
				{"username", Convert::ToString(account.username)},
				{"enforced", account.enforced},
				{"credentials", credentials}
			});
		}
		return {
			{"schemaVersion", vault.schemaVersion},
			{"machineId", vault.machineId},
			{"rpId", vault.rpId},
			{"accounts", accounts}
		};
	}

	localfido::Vault VaultFromJson(const json& value)
	{
		localfido::Vault vault;
		vault.schemaVersion = value.at("schemaVersion").get<int>();
		if (vault.schemaVersion != localfido::kSchemaVersion) throw std::runtime_error("Unsupported credential vault schema");
		vault.machineId = value.at("machineId").get<std::string>();
		vault.rpId = value.at("rpId").get<std::string>();
		for (const auto& item : value.at("accounts"))
		{
			localfido::AccountRecord account;
			account.sid = Convert::ToWString(item.at("sid").get<std::string>());
			account.username = Convert::ToWString(item.value("username", ""));
			account.enforced = item.value("enforced", false);
			for (const auto& credential : item.at("credentials")) account.credentials.push_back(CredentialFromJson(credential));
			vault.accounts.push_back(std::move(account));
		}
		return vault;
	}

	bool IsVaultValid(const localfido::Vault& vault)
	{
		if (vault.schemaVersion != localfido::kSchemaVersion || vault.machineId.size() != 32 ||
			vault.rpId != "wfl-" + vault.machineId + ".login.local" || vault.accounts.size() > 1024) return false;
		if (!std::all_of(vault.machineId.begin(), vault.machineId.end(), [](const unsigned char value)
			{ return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f'); })) return false;

		std::set<std::wstring> accountSids;
		for (const auto& account : vault.accounts)
		{
			if (account.sid.empty() || account.sid.size() > 184 || account.username.size() > 256 ||
				account.credentials.size() > 64 || (account.enforced && account.credentials.empty())) return false;
			PSID parsedSid = nullptr;
			const bool sidValid = ConvertStringSidToSidW(account.sid.c_str(), &parsedSid) && IsValidSid(parsedSid);
			if (parsedSid) LocalFree(parsedSid);
			std::wstring foldedSid = account.sid;
			std::transform(foldedSid.begin(), foldedSid.end(), foldedSid.begin(),
				[](const wchar_t value) { return static_cast<wchar_t>(std::towupper(value)); });
			if (!sidValid || !accountSids.insert(std::move(foldedSid)).second) return false;

			std::set<std::string> credentialIds;
			for (const auto& credential : account.credentials)
			{
				const auto credentialId = Convert::Base64URLDecode(credential.credentialId);
				const auto coseKey = Convert::Base64URLDecode(credential.cosePublicKey);
				const auto aaguid = Convert::Base64URLDecode(credential.aaguid);
				if (credential.algorithm != localfido::kEs256Algorithm || credentialId.empty() || credentialId.size() > 1024 ||
					coseKey.empty() || coseKey.size() > 1024 || aaguid.size() != 16 || credential.label.empty() ||
					credential.label.size() > 128 || credential.createdAt.size() > 64 ||
					!credentialIds.insert(credential.credentialId).second) return false;
				if (std::any_of(credential.label.begin(), credential.label.end(), [](const unsigned char value)
					{ return value < 0x20 || value == 0x7f; })) return false;
			}
		}
		return true;
	}

	bool WriteAll(HANDLE file, const BYTE* data, DWORD size, DWORD* error)
	{
		DWORD written = 0;
		if (!WriteFile(file, data, size, &written, nullptr) || written != size)
		{
			if (error) *error = GetLastError();
			return false;
		}
		return true;
	}
}

localfido::LocalCredentialStore::LocalCredentialStore() : _path(DefaultStorePath()) {}

std::wstring localfido::LocalCredentialStore::DefaultStorePath()
{
	wchar_t path[MAX_PATH]{};
	if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path))) return L"C:\\ProgramData\\Windows FIDO Logon\\credentials.dat";
	return std::wstring(path) + L"\\Windows FIDO Logon\\credentials.dat";
}

bool localfido::LocalCredentialStore::EnsureStoreDirectory(DWORD* error)
{
	const auto slash = _path.find_last_of(L"\\/");
	if (slash == std::wstring::npos)
	{
		if (error) *error = ERROR_INVALID_NAME;
		return false;
	}
	const std::wstring directory = _path.substr(0, slash);
	const int result = SHCreateDirectoryExW(nullptr, directory.c_str(), nullptr);
	if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS)
	{
		if (error) *error = result;
		return false;
	}
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FR;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
	{
		if (error) *error = GetLastError();
		return false;
	}
	const BOOL secured = SetFileSecurityW(directory.c_str(), OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor);
	const DWORD securityError = secured ? ERROR_SUCCESS : GetLastError();
	LocalFree(descriptor);
	if (!secured)
	{
		if (error) *error = securityError;
		return false;
	}
	return true;
}

bool localfido::LocalCredentialStore::ReadProtectedFile(const std::wstring& path, std::string& plaintext, DWORD* error)
{
	plaintext.clear();
	HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE)
	{
		if (error) *error = GetLastError();
		return false;
	}
	LARGE_INTEGER size{};
	if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 4 * 1024 * 1024)
	{
		if (error) *error = ERROR_FILE_INVALID;
		CloseHandle(file);
		return false;
	}
	std::vector<BYTE> encrypted(static_cast<size_t>(size.QuadPart));
	DWORD read = 0;
	const bool readOk = ReadFile(file, encrypted.data(), static_cast<DWORD>(encrypted.size()), &read, nullptr) &&
		read == static_cast<DWORD>(encrypted.size());
	const DWORD readError = readOk ? ERROR_SUCCESS : GetLastError();
	CloseHandle(file);
	if (!readOk)
	{
		if (error) *error = readError;
		return false;
	}

	DATA_BLOB input{ static_cast<DWORD>(encrypted.size()), encrypted.data() };
	DATA_BLOB output{};
	if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
	{
		if (error) *error = GetLastError();
		return false;
	}
	plaintext.assign(reinterpret_cast<const char*>(output.pbData), output.cbData);
	SecureZeroMemory(output.pbData, output.cbData);
	LocalFree(output.pbData);
	return true;
}

bool localfido::LocalCredentialStore::WriteProtectedFile(const std::wstring& path, const std::string& plaintext, DWORD* error)
{
	DATA_BLOB input{ static_cast<DWORD>(plaintext.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plaintext.data())) };
	DATA_BLOB output{};
	if (!CryptProtectData(&input, L"Windows FIDO Logon credential vault", nullptr, nullptr, nullptr,
		CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &output))
	{
		if (error) *error = GetLastError();
		return false;
	}

	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"O:SYG:SYD:P(A;;FA;;;SY)(A;;FR;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
	{
		if (error) *error = GetLastError();
		SecureZeroMemory(output.pbData, output.cbData);
		LocalFree(output.pbData);
		return false;
	}
	SECURITY_ATTRIBUTES attributes{ sizeof(attributes), descriptor, FALSE };
	HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_ALWAYS,
		FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, nullptr);
	LocalFree(descriptor);
	if (file == INVALID_HANDLE_VALUE)
	{
		if (error) *error = GetLastError();
		SecureZeroMemory(output.pbData, output.cbData);
		LocalFree(output.pbData);
		return false;
	}
	bool ok = WriteAll(file, output.pbData, output.cbData, error);
	if (ok && !FlushFileBuffers(file))
	{
		if (error) *error = GetLastError();
		ok = false;
	}
	CloseHandle(file);
	SecureZeroMemory(output.pbData, output.cbData);
	LocalFree(output.pbData);
	return ok;
}

bool localfido::LocalCredentialStore::Load(Vault& vault, DWORD* error)
{
	std::lock_guard<std::mutex> lock(_mutex);
	auto loadValid = [&](const std::wstring& path, DWORD& loadError) -> bool
	{
		std::string plaintext;
		if (!ReadProtectedFile(path, plaintext, &loadError)) return false;
		try
		{
			Vault parsed = VaultFromJson(json::parse(plaintext));
			SecureZeroMemory(plaintext.data(), plaintext.size());
			if (!IsVaultValid(parsed))
			{
				loadError = ERROR_INVALID_DATA;
				return false;
			}
			vault = std::move(parsed);
			loadError = ERROR_SUCCESS;
			return true;
		}
		catch (...)
		{
			SecureZeroMemory(plaintext.data(), plaintext.size());
			loadError = ERROR_INVALID_DATA;
			return false;
		}
	};

	DWORD primaryError = ERROR_SUCCESS;
	if (loadValid(_path, primaryError)) { if (error) *error = ERROR_SUCCESS; return true; }
	DWORD backupError = ERROR_SUCCESS;
	if (loadValid(_path + L".bak", backupError)) { if (error) *error = ERROR_SUCCESS; return true; }
	if (error) *error = primaryError != ERROR_SUCCESS ? primaryError : backupError;
	return false;
}

bool localfido::LocalCredentialStore::Save(const Vault& vault, DWORD* error)
{
	std::lock_guard<std::mutex> lock(_mutex);
	if (!IsVaultValid(vault))
	{
		if (error) *error = ERROR_INVALID_DATA;
		return false;
	}
	if (!EnsureStoreDirectory(error)) return false;
	std::string plaintext = VaultToJson(vault).dump();
	const std::wstring temporary = _path + L".tmp";
	if (!WriteProtectedFile(temporary, plaintext, error))
	{
		SecureZeroMemory(plaintext.data(), plaintext.size());
		return false;
	}
	SecureZeroMemory(plaintext.data(), plaintext.size());
	// Never overwrite the last valid backup with a corrupt primary, and retain
	// the previous policy for cross-resource rollback.
	std::optional<Vault> previousVault;
	auto readValidVault = [&](const std::wstring& path, Vault& parsed) -> bool
	{
		std::string protectedPlaintext;
		DWORD ignored = ERROR_SUCCESS;
		if (!ReadProtectedFile(path, protectedPlaintext, &ignored)) return false;
		try
		{
			parsed = VaultFromJson(json::parse(protectedPlaintext));
			SecureZeroMemory(protectedPlaintext.data(), protectedPlaintext.size());
			return IsVaultValid(parsed);
		}
		catch (...)
		{
			SecureZeroMemory(protectedPlaintext.data(), protectedPlaintext.size());
			return false;
		}
	};
	Vault previousParsed;
	if (readValidVault(_path, previousParsed))
	{
		if (!CopyFileW(_path.c_str(), (_path + L".bak").c_str(), FALSE))
		{
			if (error) *error = GetLastError();
			DeleteFileW(temporary.c_str());
			return false;
		}
		previousVault = std::move(previousParsed);
	}
	else if (readValidVault(_path + L".bak", previousParsed))
	{
		previousVault = std::move(previousParsed);
	}
	auto restorePreviousFile = [&]() -> bool
	{
		if (!previousVault) return false;
		const std::wstring rollback = _path + L".rollback";
		if (!CopyFileW((_path + L".bak").c_str(), rollback.c_str(), FALSE)) return false;
		if (MoveFileExW(rollback.c_str(), _path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
		DeleteFileW(rollback.c_str());
		return false;
	};
	const bool hasEnforcedAccounts = std::any_of(vault.accounts.begin(), vault.accounts.end(),
		[](const AccountRecord& account) { return account.enforced; });
	// Publish an enforcing registry policy before the vault that depends on it.
	// If the file replace then fails, the provider/broker registry cross-checks
	// block sign-in instead of creating an MFA bypass window.
	if (hasEnforcedAccounts && !SynchronizeEnforcedRegistry(vault, error))
	{
		const DWORD policyError = error ? *error : ERROR_WRITE_FAULT;
		if (previousVault) SynchronizeEnforcedRegistry(*previousVault, nullptr);
		DeleteFileW(temporary.c_str());
		if (error) *error = policyError;
		return false;
	}
	if (!MoveFileExW(temporary.c_str(), _path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
	{
		const DWORD moveError = GetLastError();
		if (hasEnforcedAccounts && previousVault) SynchronizeEnforcedRegistry(*previousVault, nullptr);
		if (error) *error = moveError;
		DeleteFileW(temporary.c_str());
		return false;
	}
	// When disabling the final policy, remove the Filter policy only after the
	// non-enforcing vault is durable. If registry publication fails, restore both
	// resources to the previous enforcing state.
	if (!hasEnforcedAccounts && !SynchronizeEnforcedRegistry(vault, error))
	{
		const DWORD policyError = error ? *error : ERROR_WRITE_FAULT;
		(void)restorePreviousFile();
		if (previousVault) SynchronizeEnforcedRegistry(*previousVault, nullptr);
		if (error) *error = policyError;
		return false;
	}
	return true;
}

bool localfido::LocalCredentialStore::LoadOrCreate(Vault& vault, DWORD* error)
{
	DWORD loadError = ERROR_SUCCESS;
	if (Load(vault, &loadError)) return true;
	if (loadError != ERROR_FILE_NOT_FOUND && loadError != ERROR_PATH_NOT_FOUND)
	{
		if (error) *error = loadError;
		return false;
	}
	vault = {};
	vault.machineId = GenerateHexId();
	if (vault.machineId.empty())
	{
		if (error) *error = ERROR_GEN_FAILURE;
		return false;
	}
	vault.rpId = "wfl-" + vault.machineId + ".login.local";
	return Save(vault, error);
}

std::optional<localfido::AccountRecord> localfido::LocalCredentialStore::FindAccount(const std::wstring& sid, DWORD* error)
{
	Vault vault;
	if (!LoadOrCreate(vault, error)) return std::nullopt;
	const auto it = std::find_if(vault.accounts.begin(), vault.accounts.end(), [&](const AccountRecord& item) { return _wcsicmp(item.sid.c_str(), sid.c_str()) == 0; });
	if (it == vault.accounts.end()) return std::nullopt;
	return *it;
}

bool localfido::LocalCredentialStore::UpsertAccount(const AccountRecord& account, DWORD* error)
{
	Vault vault;
	if (!LoadOrCreate(vault, error)) return false;
	const auto it = std::find_if(vault.accounts.begin(), vault.accounts.end(), [&](const AccountRecord& item) { return _wcsicmp(item.sid.c_str(), account.sid.c_str()) == 0; });
	if (it == vault.accounts.end()) vault.accounts.push_back(account); else *it = account;
	return Save(vault, error);
}

bool localfido::LocalCredentialStore::RemoveCredential(const std::wstring& sid, const std::string& credentialId, DWORD* error)
{
	Vault vault;
	if (!LoadOrCreate(vault, error)) return false;
	const auto account = std::find_if(vault.accounts.begin(), vault.accounts.end(), [&](const AccountRecord& item) { return _wcsicmp(item.sid.c_str(), sid.c_str()) == 0; });
	if (account == vault.accounts.end())
	{
		if (error) *error = ERROR_NOT_FOUND;
		return false;
	}
	const auto credential = std::find_if(account->credentials.begin(), account->credentials.end(), [&](const CredentialRecord& item) { return item.credentialId == credentialId; });
	if (credential == account->credentials.end())
	{
		if (error) *error = ERROR_NOT_FOUND;
		return false;
	}
	if (account->enforced && account->credentials.size() <= 1)
	{
		if (error) *error = ERROR_ACCESS_DENIED;
		return false;
	}
	account->credentials.erase(credential);
	return Save(vault, error);
}

bool localfido::LocalCredentialStore::SetEnforced(const std::wstring& sid, bool enforced, DWORD* error)
{
	Vault vault;
	if (!LoadOrCreate(vault, error)) return false;
	const auto account = std::find_if(vault.accounts.begin(), vault.accounts.end(), [&](const AccountRecord& item) { return _wcsicmp(item.sid.c_str(), sid.c_str()) == 0; });
	if (account == vault.accounts.end() || (enforced && account->credentials.empty()))
	{
		if (error) *error = ERROR_INVALID_STATE;
		return false;
	}
	account->enforced = enforced;
	return Save(vault, error);
}

bool localfido::LocalCredentialStore::RefreshLocalAccounts(DWORD* error)
{
	Vault vault;
	if (!LoadOrCreate(vault, error)) return false;
	bool changed = false;
	for (auto it = vault.accounts.begin(); it != vault.accounts.end();)
	{
		std::wstring currentName, computer;
		DWORD resolveError = ERROR_SUCCESS;
		if (!ResolveLocalSid(it->sid, currentName, computer, &resolveError))
		{
			if (resolveError == ERROR_NONE_MAPPED || resolveError == ERROR_NO_SUCH_USER)
			{
				it = vault.accounts.erase(it);
				changed = true;
				continue;
			}
			if (error) *error = resolveError;
			return false;
		}
		if (_wcsicmp(it->username.c_str(), currentName.c_str()) != 0)
		{
			it->username = currentName;
			changed = true;
		}
		++it;
	}
	return changed ? Save(vault, error) : SynchronizeEnforcedRegistry(vault, error);
}

std::vector<std::wstring> localfido::LocalCredentialStore::ReadEnforcedSids()
{
	RegistryReader reader(CONFIG_REGISTRY_PATH);
	return reader.GetMultiSZ(ENFORCED_SIDS_REGISTRY_VALUE);
}

bool localfido::LocalCredentialStore::IsSidEnforced(const std::wstring& sid)
{
	const auto sids = ReadEnforcedSids();
	return std::any_of(sids.begin(), sids.end(), [&](const std::wstring& value) { return _wcsicmp(value.c_str(), sid.c_str()) == 0; });
}

bool localfido::LocalCredentialStore::SynchronizeEnforcedRegistry(const Vault& vault, DWORD* error)
{
	HKEY key = nullptr;
	DWORD disposition = 0;
	const LONG openResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, CONFIG_REGISTRY_PATH, 0, nullptr, 0,
		KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &key, &disposition);
	if (openResult != ERROR_SUCCESS)
	{
		if (error) *error = openResult;
		return false;
	}
	std::vector<wchar_t> multi;
	DWORD enforcedCount = 0;
	for (const auto& account : vault.accounts)
	{
		if (!account.enforced) continue;
		multi.insert(multi.end(), account.sid.begin(), account.sid.end());
		multi.push_back(L'\0');
		++enforcedCount;
	}
	multi.push_back(L'\0');
	if (multi.size() == 1) multi.push_back(L'\0');
	LONG result = RegSetValueExW(key, ENFORCED_SIDS_REGISTRY_VALUE, 0, REG_MULTI_SZ,
		reinterpret_cast<const BYTE*>(multi.data()), static_cast<DWORD>(multi.size() * sizeof(wchar_t)));
	if (result == ERROR_SUCCESS)
	{
		const DWORD enabled = enforcedCount > 0 ? 1 : 0;
		result = RegSetValueExW(key, L"enable_filter", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&enabled), sizeof(enabled));
	}
	RegCloseKey(key);
	if (result != ERROR_SUCCESS && error) *error = result;
	return result == ERROR_SUCCESS;
}
