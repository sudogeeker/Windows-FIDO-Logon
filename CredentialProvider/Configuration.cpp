#include "Configuration.h"

#include "Logger.h"
#include "RegistryReader.h"

#include <WtsApi32.h>

void Configuration::Load()
{
	RegistryReader registry(CONFIG_REGISTRY_PATH);
	debugLog = registry.GetBool(L"debug_log");
	noDefault = registry.GetBool(L"no_default");
	isRemoteSession = GetSystemMetrics(SM_REMOTESESSION) != 0;
#ifdef _DEBUG
	debugLog = true;
#endif
	Logger::Get().logDebug = debugLog;
}

void Configuration::ClearSecrets()
{
	auto clear = [](std::wstring& value)
	{
		if (!value.empty()) SecureZeroMemory(value.data(), value.size() * sizeof(wchar_t));
		value.clear();
	};
	clear(credential.password);
	clear(credential.fidoPin);
	clear(credential.newPassword1);
	clear(credential.newPassword2);
}
