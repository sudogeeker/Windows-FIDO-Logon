#pragma once

#include "scenario.h"

#include <Windows.h>
#include <string>

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
	NewPasswordLabel,
	ConfirmPasswordLabel,
	ContinueButton,
	VerifyKeyButton,
	ChangePasswordButton,
	SelectUserAndPasswordPrompt,
	LocalAccountsOnly,
	SignInVerificationUnavailable,
	MfaPolicyUnavailable,
	PreparingWindowsSignIn,
	NoSecurityKeyDetected,
	EnterPinAndTouch,
	TouchKey,
	KeyVerificationFailed,
	KeyVerificationIncomplete,
	KeyVerified,
	PasswordUpdateFailed,
	PasswordMustChange,
	PasswordVerificationFailed,
	SignInFailed,
	EnterPasswordPrompt,
	ProviderLabel,
	Count,
};

UiLanguage CurrentUiLanguage() noexcept;
PCWSTR UiText(UiTextId id) noexcept;
PCWSTR UiFieldLabel(FIELD_ID field) noexcept;
