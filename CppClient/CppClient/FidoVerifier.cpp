#include "FidoVerifier.h"

#include "Convert.h"

#include <Windows.h>
#include <bcrypt.h>
#include <cbor.h>
#include <fido.h>
#include <fido/es256.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <memory>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

using json = nlohmann::json;

namespace
{
	constexpr BYTE kUserPresent = 0x01;
	constexpr BYTE kUserVerified = 0x04;
	constexpr BYTE kAttestedCredentialData = 0x40;

	std::vector<unsigned char> Decode(const std::string& value)
	{
		return Convert::Base64URLDecode(value);
	}

	bool Sha256(const BYTE* data, size_t size, BYTE output[32])
	{
		BCRYPT_ALG_HANDLE algorithm = nullptr;
		BCRYPT_HASH_HANDLE hash = nullptr;
		DWORD objectSize = 0, bytes = 0;
		std::vector<BYTE> object;
		bool ok = false;
		if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) goto Cleanup;
		if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &bytes, 0) != 0) goto Cleanup;
		object.resize(objectSize);
		if (BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) != 0) goto Cleanup;
		if (BCryptHashData(hash, const_cast<PUCHAR>(data), static_cast<ULONG>(size), 0) != 0) goto Cleanup;
		if (BCryptFinishHash(hash, output, 32, 0) != 0) goto Cleanup;
		ok = true;
	Cleanup:
		if (hash) BCryptDestroyHash(hash);
		if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
		return ok;
	}

	bool VerifyClientData(
		const std::vector<unsigned char>& clientData,
		const std::string& expectedType,
		const std::string& expectedChallenge,
		const std::string& expectedOrigin,
		std::string& error)
	{
		try
		{
			const json value = json::parse(clientData.begin(), clientData.end());
			if (value.value("type", "") != expectedType) { error = "client data type mismatch"; return false; }
			if (value.value("challenge", "") != expectedChallenge) { error = "challenge mismatch"; return false; }
			if (value.value("origin", "") != expectedOrigin) { error = "origin mismatch"; return false; }
			if (value.value("crossOrigin", false)) { error = "cross-origin ceremony rejected"; return false; }
			return true;
		}
		catch (...)
		{
			error = "invalid client data JSON";
			return false;
		}
	}

	bool VerifyAuthenticatorData(
		const std::vector<unsigned char>& authData,
		const std::string& rpId,
		uint32_t& signCount,
		std::string& error)
	{
		if (authData.size() < 37) { error = "authenticator data is too short"; return false; }
		BYTE expectedRpHash[32]{};
		if (!Sha256(reinterpret_cast<const BYTE*>(rpId.data()), rpId.size(), expectedRpHash)) { error = "unable to hash RP ID"; return false; }
		if (!std::equal(std::begin(expectedRpHash), std::end(expectedRpHash), authData.begin())) { error = "RP ID hash mismatch"; return false; }
		const BYTE flags = authData[32];
		if ((flags & kUserPresent) == 0) { error = "user presence flag missing"; return false; }
		if ((flags & kUserVerified) == 0) { error = "user verification flag missing"; return false; }
		signCount = (static_cast<uint32_t>(authData[33]) << 24) |
			(static_cast<uint32_t>(authData[34]) << 16) |
			(static_cast<uint32_t>(authData[35]) << 8) |
			static_cast<uint32_t>(authData[36]);
		return true;
	}

	bool CoseEs256Coordinates(const std::vector<unsigned char>& cose, std::vector<unsigned char>& coordinates)
	{
		coordinates.clear();
		cbor_load_result load{};
		cbor_item_t* map = cbor_load(cose.data(), cose.size(), &load);
		if (!map || !cbor_isa_map(map) || load.read != cose.size() || cbor_map_size(map) > 32)
		{
			if (map) cbor_decref(&map);
			return false;
		}
		int algorithm = 0;
		int keyType = 0;
		int curve = 0;
		bool hasAlgorithm = false;
		bool hasKeyType = false;
		bool hasCurve = false;
		bool hasX = false;
		bool hasY = false;
		std::vector<unsigned char> x, y;
		const auto pairs = cbor_map_handle(map);
		const auto count = cbor_map_size(map);
		for (size_t index = 0; index < count; ++index)
		{
			int key = 0;
			if (cbor_isa_uint(pairs[index].key)) key = static_cast<int>(cbor_get_int(pairs[index].key));
			else if (cbor_isa_negint(pairs[index].key)) key = -1 - static_cast<int>(cbor_get_int(pairs[index].key));
			else continue;
			if (key == 1 && cbor_isa_uint(pairs[index].value))
			{
				if (hasKeyType) { cbor_decref(&map); return false; }
				hasKeyType = true;
				keyType = static_cast<int>(cbor_get_int(pairs[index].value));
			}
			else if (key == 3 && cbor_isa_negint(pairs[index].value))
			{
				if (hasAlgorithm) { cbor_decref(&map); return false; }
				hasAlgorithm = true;
				algorithm = -1 - static_cast<int>(cbor_get_int(pairs[index].value));
			}
			else if (key == -1 && cbor_isa_uint(pairs[index].value))
			{
				if (hasCurve) { cbor_decref(&map); return false; }
				hasCurve = true;
				curve = static_cast<int>(cbor_get_int(pairs[index].value));
			}
			else if ((key == -2 || key == -3) && cbor_isa_bytestring(pairs[index].value))
			{
				const auto begin = cbor_bytestring_handle(pairs[index].value);
				const auto length = cbor_bytestring_length(pairs[index].value);
				bool& seen = key == -2 ? hasX : hasY;
				if (seen || !begin || length != 32) { cbor_decref(&map); return false; }
				seen = true;
				(key == -2 ? x : y).assign(begin, begin + length);
			}
		}
		cbor_decref(&map);
		if (!hasKeyType || !hasAlgorithm || !hasCurve || !hasX || !hasY ||
			keyType != 2 || algorithm != COSE_ES256 || curve != 1 || x.size() != 32 || y.size() != 32) return false;
		coordinates.reserve(64);
		coordinates.insert(coordinates.end(), x.begin(), x.end());
		coordinates.insert(coordinates.end(), y.begin(), y.end());
		return true;
	}

	bool ExtractAttestedCredential(
		const std::vector<unsigned char>& authData,
		std::vector<unsigned char>& credentialId,
		std::vector<unsigned char>& cose,
		std::string& error)
	{
		if (authData.size() < 55 || (authData[32] & kAttestedCredentialData) == 0)
		{
			error = "attested credential data is missing";
			return false;
		}
		const size_t idLength = (static_cast<size_t>(authData[53]) << 8) | authData[54];
		const size_t coseOffset = 55 + idLength;
		if (idLength == 0 || idLength > 1024 || coseOffset >= authData.size())
		{
			error = "invalid attested credential length";
			return false;
		}
		credentialId.assign(authData.begin() + 55, authData.begin() + coseOffset);
		cbor_load_result load{};
		cbor_item_t* item = cbor_load(authData.data() + coseOffset, authData.size() - coseOffset, &load);
		if (!item || !cbor_isa_map(item) || load.read == 0)
		{
			if (item) cbor_decref(&item);
			error = "invalid COSE public key";
			return false;
		}
		cbor_decref(&item);
		cose.assign(authData.begin() + coseOffset, authData.begin() + coseOffset + load.read);
		std::vector<unsigned char> coordinates;
		if (!CoseEs256Coordinates(cose, coordinates))
		{
			error = "credential is not an ES256 public key";
			return false;
		}
		return true;
	}

	struct CredentialDeleter { void operator()(fido_cred_t* value) const { if (value) fido_cred_free(&value); } };
	using CredentialPtr = std::unique_ptr<fido_cred_t, CredentialDeleter>;
}

bool localfido::FidoVerifier::VerifyAssertion(
	const CredentialRecord& credential,
	const std::string& expectedChallenge,
	const std::string& expectedRpId,
	const std::string& expectedOrigin,
	const FIDOSignResponse& response,
	uint32_t& newSignCount,
	std::string& error)
{
	error.clear();
	if (credential.algorithm != kEs256Algorithm) { error = "unsupported credential algorithm"; return false; }
	if (response.assertions.size() != 1) { error = "exactly one assertion is required"; return false; }
	const auto& assertion = response.assertions.front();
	if (assertion.credentialid != credential.credentialId) { error = "credential does not belong to account"; return false; }

	const auto clientData = Decode(response.clientdata);
	const auto authData = Decode(assertion.authenticatordata);
	const auto signature = Decode(assertion.signaturedata);
	const auto credentialId = Decode(assertion.credentialid);
	const auto cosePublicKey = Decode(credential.cosePublicKey);
	std::vector<unsigned char> publicKey;
	if (clientData.empty() || authData.empty() || signature.empty() || credentialId.empty() ||
		cosePublicKey.empty() || !CoseEs256Coordinates(cosePublicKey, publicKey))
	{
		error = "invalid base64url assertion field";
		return false;
	}
	if (!VerifyClientData(clientData, "webauthn.get", expectedChallenge, expectedOrigin, error)) return false;
	if (!VerifyAuthenticatorData(authData, expectedRpId, newSignCount, error)) return false;
	if (credential.signCount != 0 && (newSignCount == 0 || newSignCount <= credential.signCount))
	{
		error = "signature counter did not increase";
		return false;
	}

	fido_assert_t* assertionHandle = fido_assert_new();
	es256_pk_t* key = es256_pk_new();
	if (!assertionHandle || !key)
	{
		if (assertionHandle) fido_assert_free(&assertionHandle);
		if (key) es256_pk_free(&key);
		error = "out of memory";
		return false;
	}
	int result = fido_assert_set_clientdata(assertionHandle, clientData.data(), clientData.size());
	if (result == FIDO_OK) result = fido_assert_set_rp(assertionHandle, expectedRpId.c_str());
	if (result == FIDO_OK) result = fido_assert_set_id(assertionHandle, 0, credentialId.data(), credentialId.size());
	if (result == FIDO_OK) result = fido_assert_set_authdata(assertionHandle, 0, authData.data(), authData.size());
	if (result == FIDO_OK) result = fido_assert_set_sig(assertionHandle, 0, signature.data(), signature.size());
	if (result == FIDO_OK) result = fido_assert_set_up(assertionHandle, FIDO_OPT_TRUE);
	if (result == FIDO_OK) result = fido_assert_set_uv(assertionHandle, FIDO_OPT_TRUE);
	if (result == FIDO_OK) result = es256_pk_from_ptr(key, publicKey.data(), publicKey.size());
	if (result == FIDO_OK) result = fido_assert_verify(assertionHandle, 0, COSE_ES256, key);
	fido_assert_free(&assertionHandle);
	es256_pk_free(&key);
	if (result != FIDO_OK)
	{
		error = std::string("assertion signature verification failed: ") + fido_strerr(result);
		return false;
	}
	return true;
}

bool localfido::FidoVerifier::VerifyRegistration(
	const std::string& expectedChallenge,
	const std::string& expectedRpId,
	const std::string& expectedOrigin,
	const std::string& attestationObject,
	const std::string& clientDataJson,
	RegistrationResult& result,
	std::string& error)
{
	error.clear();
	const auto attestation = Decode(attestationObject);
	const auto clientData = Decode(clientDataJson);
	if (attestation.empty() || clientData.empty()) { error = "invalid registration encoding"; return false; }
	if (!VerifyClientData(clientData, "webauthn.create", expectedChallenge, expectedOrigin, error)) return false;

	CredentialPtr credential(fido_cred_new());
	if (!credential) { error = "out of memory"; return false; }
	int status = fido_cred_set_type(credential.get(), COSE_ES256);
	if (status == FIDO_OK) status = fido_cred_set_rp(credential.get(), expectedRpId.c_str(), "Windows FIDO Logon");
	if (status == FIDO_OK) status = fido_cred_set_clientdata(credential.get(), clientData.data(), clientData.size());
	if (status == FIDO_OK) status = fido_cred_set_uv(credential.get(), FIDO_OPT_TRUE);
	if (status == FIDO_OK) status = fido_cred_set_attobj(credential.get(), attestation.data(), attestation.size());
	if (status != FIDO_OK)
	{
		error = std::string("registration verification failed: ") + fido_strerr(status);
		return false;
	}

	const char* formatValue = fido_cred_fmt(credential.get());
	const std::string format = formatValue ? formatValue : "";
	if (format != "none" && format != "packed") { error = "unsupported attestation format"; return false; }
	if (format == "packed")
	{
		status = fido_cred_x5c_len(credential.get()) > 0 ?
			fido_cred_verify(credential.get()) : fido_cred_verify_self(credential.get());
		if (status != FIDO_OK)
		{
			error = std::string("attestation verification failed: ") + fido_strerr(status);
			return false;
		}
	}

	const BYTE* authDataPtr = fido_cred_authdata_raw_ptr(credential.get());
	const size_t authDataSize = fido_cred_authdata_raw_len(credential.get());
	if (!authDataPtr || authDataSize == 0) { error = "registration omitted authenticator data"; return false; }
	std::vector<unsigned char> authData(authDataPtr, authDataPtr + authDataSize);
	uint32_t signCount = 0;
	if (!VerifyAuthenticatorData(authData, expectedRpId, signCount, error)) return false;

	std::vector<unsigned char> extractedId, cose;
	if (!ExtractAttestedCredential(authData, extractedId, cose, error)) return false;
	const BYTE* parsedIdPointer = fido_cred_id_ptr(credential.get());
	const size_t parsedIdLength = fido_cred_id_len(credential.get());
	if (!parsedIdPointer || parsedIdLength == 0) { error = "registration omitted credential ID"; return false; }
	const std::vector<unsigned char> parsedId(parsedIdPointer, parsedIdPointer + parsedIdLength);
	if (parsedId != extractedId) { error = "credential ID mismatch in attestation"; return false; }

	result = {};
	result.credentialId = Convert::Base64URLEncode(extractedId);
	result.cosePublicKey = Convert::Base64URLEncode(cose);
	result.aaguid = Convert::Base64URLEncode(authData.data() + 37, 16);
	result.clientDataJson = clientDataJson;
	result.authenticatorData = Convert::Base64URLEncode(authData);
	result.attestationStatement = attestationObject;
	result.attestationFormat = format;
	result.algorithm = kEs256Algorithm;
	result.signCount = signCount;
	if (result.credentialId.empty() || result.cosePublicKey.empty()) { error = "registration omitted credential material"; return false; }
	return true;
}
