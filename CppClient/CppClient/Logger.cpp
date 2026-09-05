/* * * * * * * * * * * * * * * * * * * * *
**
** Copyright	2025 NetKnights GmbH
** Author:		Nils Behlen
**
**    Licensed under the Apache License, Version 2.0 (the "License");
**    you may not use this file except in compliance with the License.
**    You may obtain a copy of the License at
**
**        http://www.apache.org/licenses/LICENSE-2.0
**
**    Unless required by applicable law or agreed to in writing, software
**    distributed under the License is distributed on an "AS IS" BASIS,
**    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
**    See the License for the specific language governing permissions and
**    limitations under the License.
**
** * * * * * * * * * * * * * * * * * * */

#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING

#include "Logger.h"
#include <Windows.h>
#include <codecvt>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <locale>

using namespace std;

void Logger::LogS(const string& message, const char* file, int line, bool isDebugMessage)
{
	// Do not log debug messages if it is not enabled
	if (!logDebug && isDebugMessage)
	{
		return;
	}

	std::lock_guard<std::mutex> lock(_mutex);
	time_t rawtime = 0;
	struct tm timeinfo{};
	char buffer[80]{};
	time(&rawtime);
	if (localtime_s(&timeinfo, &rawtime) != 0) return;
	strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", &timeinfo);
	string fullMessage = "[" + string(buffer) + "] [" + string(file) + ":" + to_string(line) + "] " + message;

	ofstream os(std::filesystem::path(logfilePath), std::ios_base::app);
	os << fullMessage << endl;

	OutputDebugStringA(fullMessage.c_str());
	OutputDebugStringA("\n");
}

void Logger::LogW(const wstring& message, const char* file, int line, bool isDebugMessage)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	string conv = converterX.to_bytes(message);
	LogS(conv, file, line, isDebugMessage);
}

void Logger::Log(const char* message, const char* file, int line, bool isDebugMessage)
{
	string msg = "";
	if (message != nullptr && message[0] != NULL)
	{
		msg = string(message);
	}
	LogS(msg, file, line, isDebugMessage);
}

void Logger::Log(const wchar_t* message, const char* file, int line, bool isDebugMessage)
{
	wstring msg = L"";
	if (message != nullptr && message[0] != NULL)
	{
		msg = wstring(message);
	}
	LogW(msg, file, line, isDebugMessage);
}

void Logger::Log(const long message, const char* file, int line, bool isDebugMessage)
{
	string i = "(long) " + to_string(message);
	LogS(i, file, line, isDebugMessage);
}

void Logger::Log(const std::string& message, const char* file, int line, bool isDebugMessage)
{
	LogS(message, file, line, isDebugMessage);
}

void Logger::Log(const std::wstring& message, const char* file, int line, bool isDebugMessage)
{
	LogW(message, file, line, isDebugMessage);
}
