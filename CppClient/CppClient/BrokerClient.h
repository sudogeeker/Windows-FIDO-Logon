#pragma once

#include "LocalFidoTypes.h"

#include <nlohmann/json_fwd.hpp>
#include <string>
#include <vector>

namespace localfido
{
	struct AccountStatus
	{
		bool found = false;
		bool enforced = false;
		std::wstring username;
		std::vector<CredentialRecord> credentials;
	};

	class BrokerClient
	{
	public:
		bool GetStatus(const std::wstring& sid, AccountStatus& status, std::wstring& error);
		bool BeginAuthentication(const std::wstring& sid, AuthenticationChallenge& challenge, std::wstring& error);
		bool BeginTest(const std::wstring& sid, AuthenticationChallenge& challenge, std::wstring& error);
		bool FinishAuthentication(const std::string& sessionId, const FIDOSignResponse& response, std::wstring& error);

		bool BeginRegistration(
			const std::wstring& sid,
			const std::wstring& username,
			const std::wstring& password,
			const std::string& label,
			AuthenticationChallenge& authorization,
			RegistrationChallenge& registration,
			std::wstring& error);
		bool AuthorizeRegistration(
			const std::string& sessionId,
			const FIDOSignResponse& response,
			RegistrationChallenge& registration,
			std::wstring& error);
		bool CommitRegistration(
			const std::string& sessionId,
			const std::string& label,
			const std::string& attestationObject,
			const std::string& clientDataJson,
			AuthenticationChallenge& proof,
			std::wstring& error);
		bool FinishRegistration(const std::string& sessionId, const FIDOSignResponse& proof, std::wstring& error);

		bool BeginRemoval(
			const std::wstring& sid,
			const std::wstring& username,
			const std::wstring& password,
			const std::string& credentialId,
			AuthenticationChallenge& authorization,
			std::wstring& error);
		bool FinishRemoval(const std::string& sessionId, const FIDOSignResponse& authorization, std::wstring& error);
		bool RemoveCredentialWithPassword(
			const std::wstring& sid,
			const std::wstring& username,
			const std::wstring& password,
			const std::string& credentialId,
			std::wstring& error);
		bool SetEnforcement(const std::wstring& sid, bool enabled, std::wstring& error, bool allowFilterConflict = false);

	private:
		bool Call(const nlohmann::json& request, nlohmann::json& response, std::wstring& error);
	};
}
