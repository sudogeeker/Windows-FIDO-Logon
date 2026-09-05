#pragma once

#include "FIDOSignResponse.h"
#include "LocalFidoTypes.h"

#include <string>

namespace localfido
{
	class FidoVerifier
	{
	public:
		static bool VerifyAssertion(
			const CredentialRecord& credential,
			const std::string& expectedChallenge,
			const std::string& expectedRpId,
			const std::string& expectedOrigin,
			const FIDOSignResponse& response,
			uint32_t& newSignCount,
			std::string& error);

		static bool VerifyRegistration(
			const std::string& expectedChallenge,
			const std::string& expectedRpId,
			const std::string& expectedOrigin,
			const std::string& attestationObject,
			const std::string& clientDataJson,
			RegistrationResult& result,
			std::string& error);
	};
}
