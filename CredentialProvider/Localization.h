#pragma once

#include "scenario.h"

#include <Windows.h>

enum class UiLanguage
{
	English,
	SimplifiedChinese
	// Add future languages here and extend Localization.cpp's text table.
};

enum class UiTextId
{
	Title,
	Subtitle,
	SelectUserAndPassword,
	LocalUserLabel,
	WindowsPasswordLabel,
	SecurityKeyPinLabel,
	UsbSecurityKeyLabel,
	NewPasswordLabel,
	ConfirmPasswordLabel,
	ContinueButton,
	VerifyKeyButton,
	ChangePasswordButton,
	SelectUserAndPasswordPrompt,
	LocalAccountsOnly,
	MfaServiceUnavailable,
	MfaPolicyUnavailable,
	PasswordAccepted,
	NoRegisteredKey,
	SelectKeyAndTouch,
	EnterPinAndTouch,
	TouchKey,
	KeyVerificationFailed,
	KeyServiceRejected,
	KeyVerified,
	PasswordsMismatch,
	PasswordMustChange,
	PasswordRejected,
	SignInFailed,
	Count,
};

UiLanguage CurrentUiLanguage() noexcept;
PCWSTR UiText(UiTextId id) noexcept;
PCWSTR UiFieldLabel(FIELD_ID field) noexcept;
