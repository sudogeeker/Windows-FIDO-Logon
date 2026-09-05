#pragma once

#include <Windows.h>

namespace i18n
{
	inline constexpr PCWSTR kEnUs[] =
	{
		L"Windows FIDO Logon",
		L"Local account password + security key",
		L"Select a local user and enter the Windows password.",
		L"Local user",
		L"Windows password",
		L"Security-key PIN",
		L"USB security key",
		L"New Windows password",
		L"Confirm new password",
		L"Continue",
		L"Verify security key",
		L"Change password",
		L"Select a local user and enter the Windows password.",
		L"This provider supports local Windows accounts only.",
		L"MFA is enforced and the local Broker is unavailable. Sign-in is blocked.",
		L"MFA policy could not be verified. Sign-in is blocked.",
		L"Password accepted. Signing in…",
		L"No registered security key is available for this account.",
		L"Select a security key, enter its PIN if requested, then touch it.",
		L"Enter the security-key PIN, then touch the key.",
		L"Touch the USB security key to approve this sign-in.",
		L"Security-key verification failed. Enter the password again.",
		L"The security-key service rejected this sign-in. Enter the password again.",
		L"Security key verified. Signing in…",
		L"The new passwords must match and may not be empty.",
		L"Your Windows password must be changed. Enter a new password twice.",
		L"Windows rejected the password. Enter it again and complete security-key verification.",
		L"Sign-in failed. Check the password and security key, then try again.",
	};
}
