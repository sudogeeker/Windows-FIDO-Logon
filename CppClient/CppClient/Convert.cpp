/*
 * Copyright 2024-2025 NetKnights GmbH
 * Licensed under the Apache License, Version 2.0.
 */

#include "Convert.h"

#include <Windows.h>
#include <algorithm>
#include <cstdint>
#include <limits>

namespace
{
	constexpr char kBase64Alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	int Base64Value(const unsigned char value)
	{
		if (value >= 'A' && value <= 'Z') return value - 'A';
		if (value >= 'a' && value <= 'z') return value - 'a' + 26;
		if (value >= '0' && value <= '9') return value - '0' + 52;
		if (value == '+') return 62;
		if (value == '/') return 63;
		return -1;
	}

	std::vector<unsigned char> DecodeBase64Strict(const std::string& input)
	{
		if (input.empty()) return {};

		size_t padding = 0;
		while (padding < input.size() && input[input.size() - 1 - padding] == '=') ++padding;
		if (padding > 2) return {};
		const size_t encodedLength = input.size() - padding;
		if (encodedLength % 4 == 1) return {};
		if (padding != 0)
		{
			if (input.size() % 4 != 0) return {};
			const size_t requiredPadding = (4 - (encodedLength % 4)) % 4;
			if (requiredPadding != padding) return {};
		}

		std::vector<unsigned char> decoded;
		decoded.reserve((encodedLength * 6) / 8);
		uint32_t accumulator = 0;
		int bits = 0;
		int lastValue = 0;
		for (size_t index = 0; index < encodedLength; ++index)
		{
			const int value = Base64Value(static_cast<unsigned char>(input[index]));
			if (value < 0) return {};
			lastValue = value;
			accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
			bits += 6;
			if (bits >= 8)
			{
				bits -= 8;
				decoded.push_back(static_cast<unsigned char>((accumulator >> bits) & 0xff));
			}
		}

		// Reject alternate encodings whose unused trailing bits are non-zero.
		if ((encodedLength % 4 == 2 && (lastValue & 0x0f) != 0) ||
			(encodedLength % 4 == 3 && (lastValue & 0x03) != 0)) return {};
		return decoded;
	}
}

std::string Convert::ToString(const std::wstring& value)
{
	if (value.empty()) return {};
	if (value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) return {};
	const int required = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
		static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
	if (required <= 0) return {};
	std::string result(static_cast<size_t>(required), '\0');
	if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
		result.data(), required, nullptr, nullptr) != required) return {};
	return result;
}

std::wstring Convert::ToWString(const std::string& value)
{
	if (value.empty()) return {};
	if (value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) return {};
	const int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
		static_cast<int>(value.size()), nullptr, 0);
	if (required <= 0) return {};
	std::wstring result(static_cast<size_t>(required), L'\0');
	if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()),
		result.data(), required) != required) return {};
	return result;
}

std::vector<unsigned char> Convert::Base64Decode(const std::string& value)
{
	return DecodeBase64Strict(value);
}

std::vector<unsigned char> Convert::Base64URLDecode(const std::string& value)
{
	if (value.empty() || value.size() % 4 == 1) return {};
	std::string base64;
	base64.reserve(value.size());
	for (const unsigned char character : value)
	{
		if ((character >= 'A' && character <= 'Z') ||
			(character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9'))
		{
			base64.push_back(static_cast<char>(character));
		}
		else if (character == '-') base64.push_back('+');
		else if (character == '_') base64.push_back('/');
		else return {};
	}
	return DecodeBase64Strict(base64);
}

std::string Convert::Base64Encode(const unsigned char* data, const size_t size, const bool padded)
{
	if (data == nullptr && size != 0) return {};
	std::string result;
	result.reserve(((size + 2) / 3) * 4);
	for (size_t index = 0; index < size; index += 3)
	{
		const uint32_t first = data[index];
		const uint32_t second = index + 1 < size ? data[index + 1] : 0;
		const uint32_t third = index + 2 < size ? data[index + 2] : 0;
		const uint32_t block = (first << 16) | (second << 8) | third;
		result.push_back(kBase64Alphabet[(block >> 18) & 0x3f]);
		result.push_back(kBase64Alphabet[(block >> 12) & 0x3f]);
		if (index + 1 < size) result.push_back(kBase64Alphabet[(block >> 6) & 0x3f]);
		else if (padded) result.push_back('=');
		if (index + 2 < size) result.push_back(kBase64Alphabet[block & 0x3f]);
		else if (padded) result.push_back('=');
	}
	return result;
}

std::string Convert::Base64Encode(const std::vector<unsigned char>& data, const bool padded)
{
	return Base64Encode(data.data(), data.size(), padded);
}

std::string Convert::Base64URLEncode(const unsigned char* data, const size_t size, const bool padded)
{
	std::string result = Base64Encode(data, size, padded);
	std::replace(result.begin(), result.end(), '+', '-');
	std::replace(result.begin(), result.end(), '/', '_');
	return result;
}

std::string Convert::Base64URLEncode(const std::vector<unsigned char>& data, const bool padded)
{
	return Base64URLEncode(data.data(), data.size(), padded);
}
