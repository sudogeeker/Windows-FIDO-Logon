/*
 * Derived from the original Apache-2.0 privacyIDEA Credential Provider FIDO
 * integration. Copyright 2025 NetKnights GmbH.
 */
#include "FIDODevice.h"

#include "Convert.h"
#include "FIDOException.h"
#include "Logger.h"

#include <Windows.h>
#include <bcrypt.h>
#include <cbor.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <utility>

#pragma comment(lib, "Bcrypt.lib")

namespace
{
	constexpr size_t kMaximumDevices = 32;
	constexpr int kCeremonyTimeoutMs = 120000;
	constexpr DWORD kTouchPollIntervalMs = 200;
	constexpr int kTouchStatusWaitMs = 50;

	struct DeviceDeleter
	{
		void operator()(fido_dev_t* value) const
		{
			if (!value) return;
			fido_dev_close(value);
			fido_dev_free(&value);
		}
	};
	struct DeviceInfoDeleter
	{
		void operator()(fido_dev_info_t* value) const { if (value) fido_dev_info_free(&value, kMaximumDevices); }
	};
	struct CredentialDeleter
	{
		void operator()(fido_cred_t* value) const { if (value) fido_cred_free(&value); }
	};
	struct AssertionDeleter
	{
		void operator()(fido_assert_t* value) const { if (value) fido_assert_free(&value); }
	};

	using DevicePtr = std::unique_ptr<fido_dev_t, DeviceDeleter>;
	using DeviceInfoPtr = std::unique_ptr<fido_dev_info_t, DeviceInfoDeleter>;
	using CredentialPtr = std::unique_ptr<fido_cred_t, CredentialDeleter>;
	using AssertionPtr = std::unique_ptr<fido_assert_t, AssertionDeleter>;

	DevicePtr Open(const std::string& path, int& status)
	{
		DevicePtr device(fido_dev_new());
		if (!device) { status = FIDO_ERR_INTERNAL; return {}; }
		status = fido_dev_set_timeout(device.get(), 5000);
		if (status != FIDO_OK) return {};
		status = fido_dev_open(device.get(), path.c_str());
		if (status != FIDO_OK) return {};
		return device;
	}

	bool IsWindowsUsbHidPath(const std::string& path)
	{
		std::string lower = path;
		std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
		return lower.find("hid#") != std::string::npos && lower.find("windows://hello") == std::string::npos;
	}

	bool AddMapPair(cbor_item_t* map, const char* key, cbor_item_t* value)
	{
		cbor_item_t* keyItem = cbor_build_string(key);
		if (!keyItem || !value)
		{
			if (keyItem) cbor_decref(&keyItem);
			if (value) cbor_decref(&value);
			return false;
		}
		cbor_pair pair{ keyItem, value };
		if (!cbor_map_add(map, pair))
		{
			cbor_decref(&keyItem);
			cbor_decref(&value);
			return false;
		}
		return true;
	}
}

std::vector<FIDODevice> FIDODevice::GetDevices(bool log)
{
	fido_init(FIDO_DISABLE_U2F_FALLBACK);
	DeviceInfoPtr list(fido_dev_info_new(kMaximumDevices));
	if (!list) return {};
	size_t found = 0;
	const int status = fido_dev_info_manifest(list.get(), kMaximumDevices, &found);
	if (status != FIDO_OK)
	{
		if (log) WflError("Unable to enumerate FIDO2 USB devices: " + std::string(fido_strerr(status)));
		return {};
	}
	std::vector<FIDODevice> devices;
	for (size_t index = 0; index < found; ++index)
	{
		const fido_dev_info_t* info = fido_dev_info_ptr(list.get(), index);
		const char* path = info ? fido_dev_info_path(info) : nullptr;
		if (!path || !IsWindowsUsbHidPath(path)) continue;
		FIDODevice device(info, log);
		if (device._isFido2 && device._supportsEs256) devices.push_back(std::move(device));
	}
	return devices;
}

int FIDODevice::SelectByTouch(const std::vector<FIDODevice>& devices, size_t& selected,
	const std::function<bool()>& shouldContinue)
{
	selected = 0;
	if (devices.size() < 2) return FIDO_ERR_INVALID_ARGUMENT;

	struct Candidate
	{
		size_t index;
		DevicePtr device;
		bool pending = false;
	};
	std::vector<Candidate> candidates;
	candidates.reserve(devices.size());
	int lastError = FIDO_ERR_NOTFOUND;
	for (size_t index = 0; index < devices.size(); ++index)
	{
		int status = FIDO_OK;
		auto device = Open(devices[index]._path, status);
		if (!device)
		{
			lastError = status;
			continue;
		}
		candidates.push_back({ index, std::move(device), false });
	}

	auto cancelPending = [&]()
	{
		for (auto& candidate : candidates)
		{
			if (!candidate.pending) continue;
			fido_dev_cancel(candidate.device.get());
			candidate.pending = false;
		}
	};

	size_t pendingCount = 0;
	for (auto& candidate : candidates)
	{
		const int status = fido_dev_get_touch_begin(candidate.device.get());
		if (status != FIDO_OK)
		{
			lastError = status;
			continue;
		}
		candidate.pending = true;
		++pendingCount;
	}
	if (pendingCount == 0) return lastError;

	const ULONGLONG deadline = GetTickCount64() + kCeremonyTimeoutMs;
	while (GetTickCount64() < deadline)
	{
		if (shouldContinue && !shouldContinue())
		{
			cancelPending();
			return FIDO_ERR_KEEPALIVE_CANCEL;
		}
		Sleep(kTouchPollIntervalMs);
		for (auto& candidate : candidates)
		{
			if (!candidate.pending) continue;
			int touched = 0;
			const int status = fido_dev_get_touch_status(candidate.device.get(), &touched, kTouchStatusWaitMs);
			if (status != FIDO_OK)
			{
				lastError = status;
				candidate.pending = false;
				if (--pendingCount == 0) return lastError;
				continue;
			}
			if (!touched) continue;
			selected = candidate.index;
			candidate.pending = false;
			cancelPending();
			return FIDO_OK;
		}
	}

	cancelPending();
	return FIDO_ERR_USER_ACTION_TIMEOUT;
}

FIDODevice::FIDODevice(const fido_dev_info_t* info, bool log)
{
	if (!info) return;
	if (const char* value = fido_dev_info_path(info)) _path = value;
	if (const char* value = fido_dev_info_manufacturer_string(info)) _manufacturer = value;
	if (const char* value = fido_dev_info_product_string(info)) _product = value;
	const int status = ReadCapabilities();
	if (status != FIDO_OK && log) WflError("Rejected non-CTAP2/ES256 device " + ToString());
}

int FIDODevice::ReadCapabilities()
{
	int status = FIDO_OK;
	auto device = Open(_path, status);
	if (!device) return status;
	_isFido2 = fido_dev_is_fido2(device.get()) != 0;
	_hasPin = fido_dev_has_pin(device.get()) != 0;
	_hasUV = fido_dev_has_uv(device.get()) != 0 || _hasPin;
	if (!_isFido2) return FIDO_ERR_UNSUPPORTED_OPTION;
	fido_cbor_info_t* info = fido_cbor_info_new();
	if (!info) return FIDO_ERR_INTERNAL;
	status = fido_dev_get_cbor_info(device.get(), info);
	if (status == FIDO_OK)
	{
		for (size_t index = 0; index < fido_cbor_info_algorithm_count(info); ++index)
			if (fido_cbor_info_algorithm_cose(info, index) == COSE_ES256) _supportsEs256 = true;
	}
	fido_cbor_info_free(&info);
	return status;
}

int FIDODevice::Sign(const FIDOSignRequest& request, const std::string& origin, const std::string& pin,
	FIDOSignResponse& response) const
{
	response = {};
	if (!_isFido2 || !_supportsEs256 || request.allowCredentials.empty()) return FIDO_ERR_INVALID_ARGUMENT;
	int status = FIDO_OK;
	auto device = Open(_path, status);
	if (!device) return status;
	AssertionPtr assertion(fido_assert_new());
	if (!assertion) return FIDO_ERR_INTERNAL;
	for (const auto& allowed : request.allowCredentials)
	{
		const auto id = Convert::Base64URLDecode(allowed.id);
		if (id.empty() || (status = fido_assert_allow_cred(assertion.get(), id.data(), id.size())) != FIDO_OK) return status;
	}
	const std::string clientData = "{\"type\":\"webauthn.get\",\"challenge\":\"" + request.challenge +
		"\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
	if ((status = fido_assert_set_clientdata(assertion.get(), reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size())) != FIDO_OK ||
		(status = fido_assert_set_rp(assertion.get(), request.rpId.c_str())) != FIDO_OK ||
		(status = fido_assert_set_up(assertion.get(), FIDO_OPT_TRUE)) != FIDO_OK ||
		(status = fido_assert_set_uv(assertion.get(), FIDO_OPT_TRUE)) != FIDO_OK ||
		(status = fido_dev_set_timeout(device.get(), kCeremonyTimeoutMs)) != FIDO_OK) return status;
	status = fido_dev_get_assert(device.get(), assertion.get(), pin.empty() ? nullptr : pin.c_str());
	if (status != FIDO_OK) return status;
	response.clientdata = Convert::Base64URLEncode(reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size());
	for (size_t index = 0; index < fido_assert_count(assertion.get()); ++index)
	{
		FIDOAssertionData item;
		item.credentialid = Convert::Base64URLEncode(fido_assert_id_ptr(assertion.get(), index), fido_assert_id_len(assertion.get(), index));
		item.authenticatordata = Convert::Base64URLEncode(fido_assert_authdata_raw_ptr(assertion.get(), index), fido_assert_authdata_raw_len(assertion.get(), index));
		item.signaturedata = Convert::Base64URLEncode(fido_assert_sig_ptr(assertion.get(), index), fido_assert_sig_len(assertion.get(), index));
		item.userHandle = Convert::Base64URLEncode(fido_assert_user_id_ptr(assertion.get(), index), fido_assert_user_id_len(assertion.get(), index));
		response.assertions.push_back(std::move(item));
	}
	return response.assertions.empty() ? FIDO_ERR_NO_CREDENTIALS : FIDO_OK;
}

std::optional<FIDORegistrationResponse> FIDODevice::Register(const FIDORegistrationRequest& request,
	const std::string& origin, const std::string& pin)
{
	if (!_isFido2 || !_supportsEs256 || !request.residentKey || !request.userVerification)
		throw FIDOException(FIDO_ERR_UNSUPPORTED_OPTION, "A CTAP2 ES256 discoverable credential with UV is required.");
	int status = FIDO_OK;
	auto device = Open(_path, status);
	if (!device) throw FIDOException(status, "Unable to open the FIDO2 USB device.");
	CredentialPtr credential(fido_cred_new());
	if (!credential) throw FIDOException(FIDO_ERR_INTERNAL, "Unable to allocate a credential.");
	const auto userId = Convert::Base64URLDecode(request.userId);
	if (userId.empty()) throw FIDOException(FIDO_ERR_INVALID_ARGUMENT, "Invalid local user ID.");
	const std::string clientData = "{\"type\":\"webauthn.create\",\"challenge\":\"" + request.challenge +
		"\",\"origin\":\"" + origin + "\",\"crossOrigin\":false}";
	if ((status = fido_cred_set_type(credential.get(), COSE_ES256)) != FIDO_OK ||
		(status = fido_cred_set_rp(credential.get(), request.rpId.c_str(), request.rpName.c_str())) != FIDO_OK ||
		(status = fido_cred_set_clientdata(credential.get(), reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size())) != FIDO_OK ||
		(status = fido_cred_set_fmt(credential.get(), "packed")) != FIDO_OK ||
		(status = fido_cred_set_user(credential.get(), userId.data(), userId.size(), request.userName.c_str(), request.userDisplayName.c_str(), nullptr)) != FIDO_OK ||
		(status = fido_cred_set_rk(credential.get(), FIDO_OPT_TRUE)) != FIDO_OK ||
		(status = fido_cred_set_uv(credential.get(), FIDO_OPT_TRUE)) != FIDO_OK) throw FIDOException(status, "Unable to configure credential creation.");
	for (const auto& excluded : request.excludeCredentials)
	{
		const auto id = Convert::Base64URLDecode(excluded);
		if (id.empty() || (status = fido_cred_exclude(credential.get(), id.data(), id.size())) != FIDO_OK)
			throw FIDOException(status, "Unable to configure the duplicate-key exclusion list.");
	}
	if ((status = fido_dev_set_timeout(device.get(), kCeremonyTimeoutMs)) != FIDO_OK ||
		(status = fido_dev_make_cred(device.get(), credential.get(), pin.empty() ? nullptr : pin.c_str())) != FIDO_OK)
		throw FIDOException(status, "Credential creation failed.");

	FIDORegistrationResponse response;
	response.credentialId = Convert::Base64URLEncode(fido_cred_id_ptr(credential.get()), fido_cred_id_len(credential.get()));
	response.clientDataJSON = Convert::Base64URLEncode(reinterpret_cast<const unsigned char*>(clientData.data()), clientData.size());
	response.authenticatorAttachment = "cross-platform";
	response.attestationObject = BuildAttestationObject(credential.get());
	if (response.credentialId.empty() || response.attestationObject.empty())
		throw FIDOException(FIDO_ERR_INTERNAL, "Authenticator returned incomplete registration data.");
	return response;
}

void FIDODevice::SetPin(const std::string& newPin, const std::string& oldPin)
{
	if (newPin.empty()) throw FIDOException(FIDO_ERR_INVALID_ARGUMENT, "A non-empty PIN is required.");
	int status = FIDO_OK;
	auto device = Open(_path, status);
	if (!device) throw FIDOException(status, "Unable to open the FIDO2 USB device.");
	status = fido_dev_set_pin(device.get(), newPin.c_str(), oldPin.empty() ? nullptr : oldPin.c_str());
	if (status != FIDO_OK) throw FIDOException(status, "Unable to set the security-key PIN.");
	_hasPin = true;
	_hasUV = true;
}

std::string FIDODevice::GenerateRandomAsBase64URL(long size)
{
	if (size <= 0 || size > 4096) return {};
	std::vector<unsigned char> bytes(static_cast<size_t>(size));
	if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
	return Convert::Base64URLEncode(bytes);
}

std::string FIDODevice::ToString() const
{
	if (!_manufacturer.empty() && !_product.empty()) return _manufacturer + " " + _product;
	if (!_product.empty()) return _product;
	if (!_manufacturer.empty()) return _manufacturer;
	return "FIDO2 USB security key";
}

std::string FIDODevice::BuildAttestationObject(fido_cred_t* credential)
{
	const char* format = fido_cred_fmt(credential);
	const auto authData = fido_cred_authdata_raw_ptr(credential);
	const auto authDataLength = fido_cred_authdata_raw_len(credential);
	const auto attStmt = fido_cred_attstmt_ptr(credential);
	const auto attStmtLength = fido_cred_attstmt_len(credential);
	if (!format || !authData || authDataLength == 0 || !attStmt || attStmtLength == 0) return {};
	cbor_load_result load{};
	cbor_item_t* statement = cbor_load(attStmt, attStmtLength, &load);
	cbor_item_t* root = cbor_new_definite_map(3);
	if (!statement || !cbor_isa_map(statement) || load.read != attStmtLength || !root)
	{
		if (statement) cbor_decref(&statement);
		if (root) cbor_decref(&root);
		return {};
	}
	if (!AddMapPair(root, "fmt", cbor_build_string(format)))
	{
		cbor_decref(&statement);
		cbor_decref(&root);
		return {};
	}
	if (!AddMapPair(root, "attStmt", statement))
	{
		cbor_decref(&root);
		return {};
	}
	if (!AddMapPair(root, "authData", cbor_build_bytestring(authData, authDataLength)))
	{
		cbor_decref(&root);
		return {};
	}
	unsigned char* encoded = nullptr;
	size_t capacity = 0;
	const size_t written = cbor_serialize_alloc(root, &encoded, &capacity);
	cbor_decref(&root);
	if (!encoded || written == 0) { free(encoded); return {}; }
	const std::string result = Convert::Base64URLEncode(encoded, written);
	free(encoded);
	return result;
}
