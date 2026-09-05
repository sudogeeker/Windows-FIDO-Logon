/*
 * Copyright 2024-2025 NetKnights GmbH
 * Licensed under the Apache License, Version 2.0.
 */
#pragma once

#include <cstddef>
#include <string>
#include <vector>

class Convert
{
public:
	static std::wstring ToWString(const std::string& value);
	static std::string ToString(const std::wstring& value);

	// Decoders are deliberately strict. Malformed or non-canonical input returns
	// an empty vector; FIDO callers already reject empty required values.
	static std::vector<unsigned char> Base64Decode(const std::string& value);
	static std::vector<unsigned char> Base64URLDecode(const std::string& value);
	static std::string Base64Encode(const unsigned char* data, size_t size, bool padded = false);
	static std::string Base64Encode(const std::vector<unsigned char>& data, bool padded = false);
	static std::string Base64URLEncode(const unsigned char* data, size_t size, bool padded = false);
	static std::string Base64URLEncode(const std::vector<unsigned char>& data, bool padded = false);
};
