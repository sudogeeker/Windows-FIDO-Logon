#pragma once

#include "LocalFidoTypes.h"

#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace localfido
{
	class LocalCredentialStore
	{
	public:
		LocalCredentialStore();

		bool Load(Vault& vault, DWORD* error = nullptr);
		bool Save(const Vault& vault, DWORD* error = nullptr);
		bool LoadOrCreate(Vault& vault, DWORD* error = nullptr);

		std::optional<AccountRecord> FindAccount(const std::wstring& sid, DWORD* error = nullptr);
		bool UpsertAccount(const AccountRecord& account, DWORD* error = nullptr);
		bool RemoveCredential(const std::wstring& sid, const std::string& credentialId, DWORD* error = nullptr);
		bool SetEnforced(const std::wstring& sid, bool enforced, DWORD* error = nullptr);
		bool RefreshLocalAccounts(DWORD* error = nullptr);

		static bool IsSidEnforced(const std::wstring& sid);
		static std::vector<std::wstring> ReadEnforcedSids();
		static std::wstring DefaultStorePath();

	private:
		bool SynchronizeEnforcedRegistry(const Vault& vault, DWORD* error);
		bool ReadProtectedFile(const std::wstring& path, std::string& plaintext, DWORD* error);
		bool WriteProtectedFile(const std::wstring& path, const std::string& plaintext, DWORD* error);
		bool EnsureStoreDirectory(DWORD* error);

		std::wstring _path;
		std::mutex _mutex;
	};
}
