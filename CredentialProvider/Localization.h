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
	UsbSecurityKeyLabel,
	Fido2UsbSecurityKeyFallback,
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
	SelectKeyAndTouch,
	EnterPinAndTouch,
	TouchKey,
	KeyVerificationFailed,
	KeyVerificationIncomplete,
	KeyVerified,
	PasswordUpdateFailed,
	PasswordMustChange,
	PasswordVerificationFailed,
	SignInFailed,
	Count,
};

UiLanguage CurrentUiLanguage() noexcept;
PCWSTR UiText(UiTextId id) noexcept;
PCWSTR UiFieldLabel(FIELD_ID field) noexcept;
std::wstring UiSecurityKeyDisplayName(const std::string& manufacturer, const std::string& product);
