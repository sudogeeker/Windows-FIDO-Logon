#pragma once

#include "FIDOSignRequest.h"
#include "FIDOSignResponse.h"

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace localfido
{
	inline constexpr int kSchemaVersion = 1;
	inline constexpr int kEs256Algorithm = -7;
	inline constexpr DWORD kBrokerProtocolVersion = 1;
	inline constexpr DWORD kMaxBrokerMessageBytes = 64 * 1024;
	inline constexpr wchar_t kBrokerPipeName[] = L"\\\\.\\pipe\\WindowsFidoLogon.Broker.v1";
	inline constexpr wchar_t kServiceName[] = L"WindowsFidoLogonBroker";
	inline constexpr wchar_t kProductDirectory[] = L"Windows FIDO Logon";

	struct CredentialRecord
	{
		std::string credentialId;
		std::string cosePublicKey;
		int algorithm = kEs256Algorithm;
		std::string aaguid;
		std::string label;
		std::string createdAt;
		uint32_t signCount = 0;
	};

	struct AccountRecord
	{
		std::wstring sid;
		std::wstring username;
		bool enforced = false;
		std::vector<CredentialRecord> credentials;
	};

	struct Vault
	{
		int schemaVersion = kSchemaVersion;
		std::string machineId;
		std::string rpId;
		std::vector<AccountRecord> accounts;
	};

	struct AuthenticationChallenge
	{
		bool enforced = false;
		std::string sessionId;
		std::string rpId;
		std::string origin;
		FIDOSignRequest request;
	};

	struct RegistrationChallenge
	{
		std::string sessionId;
		std::string rpId;
		std::string origin;
		std::string challenge;
		std::string userId;
		std::vector<std::string> excludeCredentials;
	};

	struct RegistrationResult
	{
		std::string credentialId;
		std::string cosePublicKey;
		std::string aaguid;
		std::string clientDataJson;
		std::string authenticatorData;
		std::string attestationStatement;
		std::string attestationFormat;
		int algorithm = kEs256Algorithm;
		uint32_t signCount = 0;
	};
}
