#include "Convert.h"
#include "FidoVerifier.h"

#include <Windows.h>
#include <bcrypt.h>
#include <cbor.h>
#include <fido.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

namespace
{
	void Require(bool value, const char* message)
	{
		if (!value) throw std::runtime_error(message);
	}

	std::vector<unsigned char> Sha256(const std::vector<unsigned char>& input)
	{
		BCRYPT_ALG_HANDLE algorithm = nullptr;
		BCRYPT_HASH_HANDLE hash = nullptr;
		DWORD objectSize = 0, returned = 0;
		Require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0, "open SHA-256");
		Require(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objectSize), sizeof(objectSize), &returned, 0) == 0, "SHA object size");
		std::vector<unsigned char> object(objectSize), digest(32);
		Require(BCryptCreateHash(algorithm, &hash, object.data(), objectSize, nullptr, 0, 0) == 0, "create SHA hash");
		Require(BCryptHashData(hash, const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()), 0) == 0, "hash data");
		Require(BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) == 0, "finish SHA hash");
		BCryptDestroyHash(hash);
		BCryptCloseAlgorithmProvider(algorithm, 0);
		return digest;
	}

	void Add(cbor_item_t* map, cbor_item_t* key, cbor_item_t* value)
	{
		cbor_pair pair{ key, value };
		Require(key && value && cbor_map_add(map, pair), "CBOR map insertion");
	}

	std::vector<unsigned char> Serialize(cbor_item_t* item)
	{
		unsigned char* bytes = nullptr;
		size_t capacity = 0;
		const size_t length = cbor_serialize_alloc(item, &bytes, &capacity);
		Require(bytes && length > 0, "CBOR serialization");
		std::vector<unsigned char> result(bytes, bytes + length);
		free(bytes);
		return result;
	}

	struct TestKey
	{
		BCRYPT_ALG_HANDLE algorithm = nullptr;
		BCRYPT_KEY_HANDLE key = nullptr;
		std::vector<unsigned char> x;
		std::vector<unsigned char> y;

		TestKey()
		{
			Require(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) == 0, "open ECDSA");
			Require(BCryptGenerateKeyPair(algorithm, &key, 256, 0) == 0, "generate ECDSA key");
			Require(BCryptFinalizeKeyPair(key, 0) == 0, "finalize ECDSA key");
			DWORD size = 0, returned = 0;
			Require(BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &size, 0) == 0, "ECDSA public size");
			std::vector<unsigned char> blob(size);
			Require(BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, blob.data(), size, &returned, 0) == 0, "ECDSA public export");
			const auto header = reinterpret_cast<const BCRYPT_ECCKEY_BLOB*>(blob.data());
			Require(header->cbKey == 32, "unexpected P-256 coordinate size");
			x.assign(blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32);
			y.assign(blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB) + 32, blob.end());
		}

		~TestKey()
		{
			if (key) BCryptDestroyKey(key);
			if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
		}

		std::vector<unsigned char> Sign(const std::vector<unsigned char>& digest) const
		{
			DWORD size = 0, returned = 0;
			Require(BCryptSignHash(key, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), nullptr, 0, &size, 0) == 0, "ECDSA signature size");
			std::vector<unsigned char> raw(size);
			Require(BCryptSignHash(key, nullptr, const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()), raw.data(), size, &returned, 0) == 0, "ECDSA signature");
			Require(raw.size() == 64, "unexpected ECDSA signature size");
			auto integer = [](const unsigned char* value)
			{
				size_t first = 0;
				while (first < 31 && value[first] == 0) ++first;
				std::vector<unsigned char> encoded;
				encoded.push_back(0x02);
				const bool prefix = (value[first] & 0x80) != 0;
				encoded.push_back(static_cast<unsigned char>(32 - first + (prefix ? 1 : 0)));
				if (prefix) encoded.push_back(0);
				encoded.insert(encoded.end(), value + first, value + 32);
				return encoded;
			};
			auto r = integer(raw.data());
			auto s = integer(raw.data() + 32);
			std::vector<unsigned char> der{ 0x30, static_cast<unsigned char>(r.size() + s.size()) };
			der.insert(der.end(), r.begin(), r.end());
			der.insert(der.end(), s.begin(), s.end());
			return der;
		}
	};

	std::vector<unsigned char> CoseKey(const TestKey& key)
	{
		cbor_item_t* map = cbor_new_definite_map(5);
		Add(map, cbor_build_uint8(1), cbor_build_uint8(2));             // kty: EC2
		Add(map, cbor_build_uint8(3), cbor_build_negint8(6));          // alg: -7
		Add(map, cbor_build_negint8(0), cbor_build_uint8(1));          // crv: P-256
		Add(map, cbor_build_negint8(1), cbor_build_bytestring(key.x.data(), key.x.size()));
		Add(map, cbor_build_negint8(2), cbor_build_bytestring(key.y.data(), key.y.size()));
		auto result = Serialize(map);
		cbor_decref(&map);
		return result;
	}

	std::string ClientData(const char* type, const std::string& challenge, const std::string& origin)
	{
		return std::string("{\"type\":\"") + type + "\",\"challenge\":\"" + challenge +
			"\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
	}

	std::vector<unsigned char> AuthenticatorHeader(const std::string& rpId, unsigned char flags, uint32_t count)
	{
		const std::vector<unsigned char> rpBytes(rpId.begin(), rpId.end());
		auto result = Sha256(rpBytes);
		result.push_back(flags);
		result.push_back(static_cast<unsigned char>(count >> 24));
		result.push_back(static_cast<unsigned char>(count >> 16));
		result.push_back(static_cast<unsigned char>(count >> 8));
		result.push_back(static_cast<unsigned char>(count));
		return result;
	}

	struct Fixture
	{
		std::string rpId = "wfl-00112233445566778899aabbccddeeff.login.local";
		std::string origin = "https://" + rpId;
		std::string registrationChallenge = "registration-challenge";
		std::string assertionChallenge = "assertion-challenge";
		std::vector<unsigned char> credentialId{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
		TestKey key;

		std::string AttestationObject(unsigned char flags = 0x45) const
		{
			auto authData = AuthenticatorHeader(rpId, flags, 0);
			authData.insert(authData.end(), 16, 0x2a); // AAGUID
			authData.push_back(0);
			authData.push_back(static_cast<unsigned char>(credentialId.size()));
			authData.insert(authData.end(), credentialId.begin(), credentialId.end());
			const auto cose = CoseKey(key);
			authData.insert(authData.end(), cose.begin(), cose.end());
			cbor_item_t* root = cbor_new_definite_map(3);
			Add(root, cbor_build_string("fmt"), cbor_build_string("none"));
			Add(root, cbor_build_string("authData"), cbor_build_bytestring(authData.data(), authData.size()));
			Add(root, cbor_build_string("attStmt"), cbor_new_definite_map(0));
			const auto bytes = Serialize(root);
			cbor_decref(&root);
			return Convert::Base64URLEncode(bytes);
		}

		FIDOSignResponse Assertion(unsigned char flags = 0x05, uint32_t count = 1) const
		{
			const std::string client = ClientData("webauthn.get", assertionChallenge, origin);
			std::vector<unsigned char> clientBytes(client.begin(), client.end());
			auto authData = AuthenticatorHeader(rpId, flags, count);
			auto signedData = authData;
			const auto clientHash = Sha256(clientBytes);
			signedData.insert(signedData.end(), clientHash.begin(), clientHash.end());
			const auto signature = key.Sign(Sha256(signedData));
			FIDOSignResponse response;
			response.clientdata = Convert::Base64URLEncode(clientBytes);
			FIDOAssertionData item;
			item.credentialid = Convert::Base64URLEncode(credentialId);
			item.authenticatordata = Convert::Base64URLEncode(authData);
			item.signaturedata = Convert::Base64URLEncode(signature);
			response.assertions.push_back(std::move(item));
			return response;
		}
	};
}

int main()
{
	try
	{
		fido_init(0);
		Require(Convert::Base64URLDecode("AQIDBA") == std::vector<unsigned char>({ 1, 2, 3, 4 }), "valid base64url rejected");
		Require(Convert::Base64URLDecode("AQIDBA==").empty(), "padded base64url accepted");
		Require(Convert::Base64URLDecode("AQID+_").empty(), "mixed base64 alphabet accepted");
		Require(Convert::Base64URLDecode("A").empty(), "invalid base64url length accepted");
		Require(Convert::Base64URLDecode("AB").empty(), "non-canonical base64url accepted");
		Fixture fixture;
		const std::string registrationClient = ClientData("webauthn.create", fixture.registrationChallenge, fixture.origin);
		const std::vector<unsigned char> registrationClientBytes(registrationClient.begin(), registrationClient.end());
		localfido::RegistrationResult registration;
		std::string error;
		Require(localfido::FidoVerifier::VerifyRegistration(fixture.registrationChallenge, fixture.rpId, fixture.origin,
			fixture.AttestationObject(), Convert::Base64URLEncode(registrationClientBytes), registration, error), "valid registration rejected");
		Require(!localfido::FidoVerifier::VerifyRegistration("wrong", fixture.rpId, fixture.origin,
			fixture.AttestationObject(), Convert::Base64URLEncode(registrationClientBytes), registration, error), "registration challenge tamper accepted");
		Require(!localfido::FidoVerifier::VerifyRegistration(fixture.registrationChallenge, fixture.rpId, "https://wrong",
			fixture.AttestationObject(), Convert::Base64URLEncode(registrationClientBytes), registration, error), "registration origin tamper accepted");
		Require(!localfido::FidoVerifier::VerifyRegistration(fixture.registrationChallenge, "wrong.local", fixture.origin,
			fixture.AttestationObject(), Convert::Base64URLEncode(registrationClientBytes), registration, error), "registration RP tamper accepted");
		Require(!localfido::FidoVerifier::VerifyRegistration(fixture.registrationChallenge, fixture.rpId, fixture.origin,
			fixture.AttestationObject(0x41), Convert::Base64URLEncode(registrationClientBytes), registration, error), "registration missing UV accepted");
		Require(!localfido::FidoVerifier::VerifyRegistration(fixture.registrationChallenge, fixture.rpId, fixture.origin,
			fixture.AttestationObject(0x44), Convert::Base64URLEncode(registrationClientBytes), registration, error), "registration missing UP accepted");
		Require(!localfido::FidoVerifier::VerifyRegistration(fixture.registrationChallenge, fixture.rpId, fixture.origin,
			fixture.AttestationObject(), "A", registration, error), "malformed registration encoding accepted");

		localfido::CredentialRecord record;
		record.credentialId = registration.credentialId;
		record.cosePublicKey = registration.cosePublicKey;
		record.algorithm = registration.algorithm;
		record.signCount = 0;
		uint32_t counter = 0;
		auto assertion = fixture.Assertion();
		Require(localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin,
			assertion, counter, error) && counter == 1, "valid assertion rejected");
		Require(!localfido::FidoVerifier::VerifyAssertion(record, "wrong", fixture.rpId, fixture.origin, assertion, counter, error), "assertion challenge tamper accepted");
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, "https://wrong", assertion, counter, error), "assertion origin tamper accepted");
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, "wrong.local", fixture.origin, assertion, counter, error), "assertion RP tamper accepted");
		auto wrongCredential = assertion;
		wrongCredential.assertions[0].credentialid = "AQID";
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin, wrongCredential, counter, error), "credential/SID ownership mismatch accepted");
		auto badSignature = assertion;
		badSignature.assertions[0].signaturedata[0] = badSignature.assertions[0].signaturedata[0] == 'A' ? 'B' : 'A';
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin, badSignature, counter, error), "signature tamper accepted");
		auto malformedEncoding = assertion;
		malformedEncoding.assertions[0].authenticatordata += "=";
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin, malformedEncoding, counter, error), "malformed assertion encoding accepted");
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin, fixture.Assertion(0x04), counter, error), "missing UP accepted");
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin, fixture.Assertion(0x01), counter, error), "missing UV accepted");
		record.signCount = 10;
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin, fixture.Assertion(0x05, 9), counter, error), "counter rollback accepted");
		Require(!localfido::FidoVerifier::VerifyAssertion(record, fixture.assertionChallenge, fixture.rpId, fixture.origin, fixture.Assertion(0x05, 0), counter, error), "counter reset to zero accepted");
		std::cout << "FidoVerifierTests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "FidoVerifierTests failed: " << exception.what() << "\n";
		return 1;
	}
}
