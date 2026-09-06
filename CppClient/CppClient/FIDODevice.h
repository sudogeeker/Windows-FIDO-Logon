#pragma once

#include "FIDORegistrationRequest.h"
#include "FIDORegistrationResponse.h"
#include "FIDOSignRequest.h"
#include "FIDOSignResponse.h"

#include <fido.h>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// USB HID, CTAP2, ES256-only authenticator wrapper used by LogonUI and the manager.
class FIDODevice
{
public:
	static std::vector<FIDODevice> GetDevices(bool log = true);
	static int SelectByTouch(const std::vector<FIDODevice>& devices, size_t& selected,
		const std::function<bool()>& shouldContinue = {});

	FIDODevice(const fido_dev_info_t* info, bool log = true);
	FIDODevice() = default;

	int Sign(const FIDOSignRequest& request, const std::string& origin, const std::string& pin,
		FIDOSignResponse& response) const;
	std::optional<FIDORegistrationResponse> Register(const FIDORegistrationRequest& request,
		const std::string& origin, const std::string& pin);
	void SetPin(const std::string& newPin, const std::string& oldPin = "");

	std::string GetPath() const { return _path; }
	std::string GetManufacturer() const { return _manufacturer; }
	std::string GetProduct() const { return _product; }
	bool HasPin() const noexcept { return _hasPin; }
	bool HasUV() const noexcept { return _hasUV; }
	std::string ToString() const;
	static std::string GenerateRandomAsBase64URL(long size);

private:
	int ReadCapabilities();
	static std::string BuildAttestationObject(fido_cred_t* credential);

	std::string _path;
	std::string _manufacturer;
	std::string _product;
	bool _hasPin = false;
	bool _hasUV = false;
	bool _isFido2 = false;
	bool _supportsEs256 = false;
};
