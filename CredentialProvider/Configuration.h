#pragma once

#include "Mode.h"
#include <Windows.h>
#include <credentialprovider.h>
#include <string>

class Configuration
{
public:
	void Load();
	void ClearSecrets();
	~Configuration() { ClearSecrets(); }

	bool debugLog = false;
	bool noDefault = false;
	bool isRemoteSession = false;
	Mode mode = Mode::USERNAME_PASSWORD;

	struct ProviderState
	{
		ICredentialProviderEvents* events = nullptr;
		UINT_PTR context = 0;
		CREDENTIAL_PROVIDER_USAGE_SCENARIO scenario = CPUS_INVALID;
		DWORD flags = 0;
	} provider;

	struct CredentialState
	{
		std::wstring username;
		std::wstring domain;
		std::wstring password;
		std::wstring fidoPin;
		std::wstring newPassword1;
		std::wstring newPassword2;
		bool passwordMustChange = false;
	} credential;
};
