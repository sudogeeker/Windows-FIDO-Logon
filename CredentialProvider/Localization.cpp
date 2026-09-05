#include "Localization.h"

#include "i18n/en-US.h"
#include "i18n/zh-CN.h"

namespace
{
	UiLanguage DetectLanguage() noexcept
	{
		const LANGID language = GetSystemDefaultUILanguage();
		return PRIMARYLANGID(language) == LANG_CHINESE ? UiLanguage::SimplifiedChinese : UiLanguage::English;
	}

	const PCWSTR* TextTable() noexcept
	{
		return CurrentUiLanguage() == UiLanguage::SimplifiedChinese ? i18n::kZhCn : i18n::kEnUs;
	}
}

UiLanguage CurrentUiLanguage() noexcept
{
	static const UiLanguage language = DetectLanguage();
	return language;
}

PCWSTR UiText(UiTextId id) noexcept
{
	const size_t index = static_cast<size_t>(id);
	if (index >= static_cast<size_t>(UiTextId::Count)) return L"";
	return TextTable()[index];
}

PCWSTR UiFieldLabel(FIELD_ID field) noexcept
{
	switch (field)
	{
	case FID_LARGE_TEXT: return UiText(UiTextId::Title);
	case FID_SMALL_TEXT: return UiText(UiTextId::Subtitle);
	case FID_USERNAME: return UiText(UiTextId::LocalUserLabel);
	case FID_PASSWORD: return UiText(UiTextId::WindowsPasswordLabel);
	case FID_FIDO_PIN: return UiText(UiTextId::SecurityKeyPinLabel);
	case FID_DEVICE_SELECT: return UiText(UiTextId::UsbSecurityKeyLabel);
	case FID_NEW_PASS_1: return UiText(UiTextId::NewPasswordLabel);
	case FID_NEW_PASS_2: return UiText(UiTextId::ConfirmPasswordLabel);
	default: return L"";
	}
}
