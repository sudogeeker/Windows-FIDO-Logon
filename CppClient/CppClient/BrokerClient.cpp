#include "BrokerClient.h"

#include "Convert.h"

#include <Windows.h>
#include <nlohmann/json.hpp>
#include <vector>

using json = nlohmann::json;

namespace
{
	void ClearJsonSecret(json& value, const char* name) noexcept
	{
		if (!value.contains(name) || !value[name].is_string()) return;
		auto& secret = value[name].get_ref<std::string&>();
		if (!secret.empty()) SecureZeroMemory(secret.data(), secret.size());
		secret.clear();
	}

	bool IsTrustedPipeServer(HANDLE pipe)
	{
		using GetServerProcessId = BOOL(WINAPI*)(HANDLE, PULONG);
		const auto function = reinterpret_cast<GetServerProcessId>(
			GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetNamedPipeServerProcessId"));
		ULONG processId = 0;
		if (!function || !function(pipe, &processId) || processId == 0) return false;
		HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
		if (!process) return false;
		HANDLE token = nullptr;
		const BOOL opened = OpenProcessToken(process, TOKEN_QUERY, &token);
		CloseHandle(process);
		if (!opened) return false;
		DWORD size = 0;
		GetTokenInformation(token, TokenUser, nullptr, 0, &size);
		std::vector<BYTE> buffer(size);
		const BOOL queried = size != 0 && GetTokenInformation(token, TokenUser, buffer.data(), size, &size);
		const bool trusted = queried && IsWellKnownSid(
			reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, WinLocalSystemSid);
		CloseHandle(token);
		return trusted;
	}

	json AssertionToJson(const FIDOSignResponse& response)
	{
		json assertions = json::array();
		for (const auto& item : response.assertions)
		{
			assertions.push_back({
				{"credentialId", item.credentialid},
				{"authenticatorData", item.authenticatordata},
				{"signature", item.signaturedata},
				{"userHandle", item.userHandle}
			});
		}
		return { {"clientData", response.clientdata}, {"assertions", assertions} };
	}

	localfido::CredentialRecord CredentialFromJson(const json& item)
	{
		localfido::CredentialRecord record;
		record.credentialId = item.at("credentialId").get<std::string>();
		record.cosePublicKey = item.value("cosePublicKey", "");
		record.algorithm = item.value("algorithm", localfido::kEs256Algorithm);
		record.aaguid = item.value("aaguid", "");
		record.label = item.value("label", "Security key");
		record.createdAt = item.value("createdAt", "");
		record.signCount = item.value("signCount", 0u);
		return record;
	}

	bool ParseAuthenticationChallenge(const json& value, localfido::AuthenticationChallenge& result)
	{
		result = {};
		result.enforced = value.value("enforced", false);
		if (!result.enforced) return true;
		result.sessionId = value.at("sessionId").get<std::string>();
		result.rpId = value.at("rpId").get<std::string>();
		result.origin = value.at("origin").get<std::string>();
		result.request.rpId = result.rpId;
		result.request.challenge = value.at("challenge").get<std::string>();
		result.request.userVerification = "required";
		result.request.type = "webauthn";
		result.request.timeout = 120000;
		for (const auto& id : value.at("credentialIds"))
		{
			AllowCredential credential;
			credential.id = id.get<std::string>();
			credential.transports = { "usb" };
			result.request.allowCredentials.push_back(std::move(credential));
		}
		return true;
	}

	bool ParseRegistrationChallenge(const json& value, localfido::RegistrationChallenge& result)
	{
		result = {};
		result.sessionId = value.at("sessionId").get<std::string>();
		result.rpId = value.at("rpId").get<std::string>();
		result.origin = value.at("origin").get<std::string>();
		result.challenge = value.at("challenge").get<std::string>();
		result.userId = value.at("userId").get<std::string>();
		result.excludeCredentials = value.value("excludeCredentials", std::vector<std::string>{});
		return true;
	}
}

bool localfido::BrokerClient::Call(const json& request, json& response, std::wstring& error)
{
	error.clear();
	if (!WaitNamedPipeW(kBrokerPipeName, 3000))
	{
		error = L"Windows FIDO Logon Broker is unavailable.";
		return false;
	}
	HANDLE pipe = CreateFileW(kBrokerPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
	if (pipe == INVALID_HANDLE_VALUE)
	{
		error = L"Unable to connect to Windows FIDO Logon Broker.";
		return false;
	}
	if (!IsTrustedPipeServer(pipe))
	{
		CloseHandle(pipe);
		error = L"The local Broker pipe is not owned by LocalSystem.";
		return false;
	}
	DWORD mode = PIPE_READMODE_MESSAGE;
	SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);
	json envelope = request;
	envelope["version"] = kBrokerProtocolVersion;
	std::string serialized;
	try
	{
		serialized = envelope.dump();
	}
	catch (...)
	{
		ClearJsonSecret(envelope, "password");
		CloseHandle(pipe);
		error = L"Unable to serialize Broker request.";
		return false;
	}
	ClearJsonSecret(envelope, "password");
	if (serialized.size() > kMaxBrokerMessageBytes)
	{
		SecureZeroMemory(serialized.data(), serialized.size());
		CloseHandle(pipe);
		error = L"Broker request is too large.";
		return false;
	}
	DWORD written = 0;
	if (!WriteFile(pipe, serialized.data(), static_cast<DWORD>(serialized.size()), &written, nullptr) || written != serialized.size())
	{
		SecureZeroMemory(serialized.data(), serialized.size());
		CloseHandle(pipe);
		error = L"Unable to write Broker request.";
		return false;
	}
	SecureZeroMemory(serialized.data(), serialized.size());
	std::vector<char> buffer(kMaxBrokerMessageBytes);
	DWORD read = 0;
	if (!ReadFile(pipe, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
	{
		CloseHandle(pipe);
		error = L"Unable to read Broker response.";
		return false;
	}
	const char acknowledgement = 1;
	DWORD acknowledgementSize = 0;
	(void)WriteFile(pipe, &acknowledgement, 1, &acknowledgementSize, nullptr);
	CloseHandle(pipe);
	try
	{
		response = json::parse(buffer.begin(), buffer.begin() + read);
		if (!response.value("ok", false))
		{
			error = Convert::ToWString(response.value("error", "Broker rejected the request."));
			return false;
		}
		return true;
	}
	catch (...)
	{
		error = L"Broker returned invalid data.";
		return false;
	}
}

bool localfido::BrokerClient::GetStatus(const std::wstring& sid, AccountStatus& status, std::wstring& error)
{
	json response;
	if (!Call({ {"op", "status"}, {"sid", Convert::ToString(sid)} }, response, error)) return false;
	status = {};
	status.found = response.value("found", false);
	status.enforced = response.value("enforced", false);
	status.username = Convert::ToWString(response.value("username", ""));
	for (const auto& item : response.value("credentials", json::array())) status.credentials.push_back(CredentialFromJson(item));
	return true;
}

bool localfido::BrokerClient::BeginAuthentication(const std::wstring& sid, AuthenticationChallenge& challenge, std::wstring& error)
{
	json response;
	if (!Call({ {"op", "begin_auth"}, {"sid", Convert::ToString(sid)} }, response, error)) return false;
	try { return ParseAuthenticationChallenge(response, challenge); }
	catch (...) { error = L"Broker returned an invalid authentication challenge."; return false; }
}

bool localfido::BrokerClient::BeginTest(const std::wstring& sid, AuthenticationChallenge& challenge, std::wstring& error)
{
	json response;
	if (!Call({ {"op", "begin_test"}, {"sid", Convert::ToString(sid)} }, response, error)) return false;
	try { return ParseAuthenticationChallenge(response, challenge); }
	catch (...) { error = L"Broker returned an invalid test challenge."; return false; }
}

bool localfido::BrokerClient::FinishAuthentication(const std::string& sessionId, const FIDOSignResponse& assertion, std::wstring& error)
{
	json response;
	return Call({ {"op", "finish_auth"}, {"sessionId", sessionId}, {"assertion", AssertionToJson(assertion)} }, response, error);
}

bool localfido::BrokerClient::BeginRegistration(
	const std::wstring& sid,
	const std::wstring& username,
	const std::wstring& password,
	const std::string& label,
	AuthenticationChallenge& authorization,
	RegistrationChallenge& registration,
	std::wstring& error)
{
	json response;
	json request = {
		{"op", "begin_registration"},
		{"sid", Convert::ToString(sid)},
		{"username", Convert::ToString(username)},
		{"password", Convert::ToString(password)},
		{"label", label}
	};
	const bool ok = Call(request, response, error);
	ClearJsonSecret(request, "password");
	if (!ok) return false;
	try
	{
		if (response.value("authorizationRequired", false)) return ParseAuthenticationChallenge(response.at("authorization"), authorization);
		return ParseRegistrationChallenge(response.at("registration"), registration);
	}
	catch (...) { error = L"Broker returned an invalid registration challenge."; return false; }
}

bool localfido::BrokerClient::AuthorizeRegistration(
	const std::string& sessionId,
	const FIDOSignResponse& assertion,
	RegistrationChallenge& registration,
	std::wstring& error)
{
	json response;
	if (!Call({ {"op", "authorize_registration"}, {"sessionId", sessionId}, {"assertion", AssertionToJson(assertion)} }, response, error)) return false;
	try { return ParseRegistrationChallenge(response.at("registration"), registration); }
	catch (...) { error = L"Broker returned an invalid registration challenge."; return false; }
}

bool localfido::BrokerClient::CommitRegistration(
	const std::string& sessionId,
	const std::string& label,
	const std::string& attestationObject,
	const std::string& clientDataJson,
	AuthenticationChallenge& proof,
	std::wstring& error)
{
	json response;
	if (!Call({
		{"op", "commit_registration"}, {"sessionId", sessionId}, {"label", label},
		{"attestationObject", attestationObject}, {"clientDataJson", clientDataJson}
	}, response, error)) return false;
	try { return ParseAuthenticationChallenge(response.at("proof"), proof); }
	catch (...) { error = L"Broker returned an invalid proof-of-possession challenge."; return false; }
}

bool localfido::BrokerClient::FinishRegistration(const std::string& sessionId, const FIDOSignResponse& proof, std::wstring& error)
{
	json response;
	return Call({ {"op", "finish_registration"}, {"sessionId", sessionId}, {"assertion", AssertionToJson(proof)} }, response, error);
}

bool localfido::BrokerClient::BeginRemoval(
	const std::wstring& sid,
	const std::wstring& username,
	const std::wstring& password,
	const std::string& credentialId,
	AuthenticationChallenge& authorization,
	std::wstring& error)
{
	json response;
	json request = {
		{"op", "begin_remove"}, {"sid", Convert::ToString(sid)}, {"username", Convert::ToString(username)},
		{"password", Convert::ToString(password)}, {"credentialId", credentialId}
	};
	const bool ok = Call(request, response, error);
	ClearJsonSecret(request, "password");
	if (!ok) return false;
	try { return ParseAuthenticationChallenge(response.at("authorization"), authorization); }
	catch (...) { error = L"Broker returned an invalid removal authorization challenge."; return false; }
}

bool localfido::BrokerClient::FinishRemoval(const std::string& sessionId, const FIDOSignResponse& authorization, std::wstring& error)
{
	json response;
	return Call({ {"op", "finish_remove"}, {"sessionId", sessionId}, {"assertion", AssertionToJson(authorization)} }, response, error);
}

bool localfido::BrokerClient::SetEnforcement(const std::wstring& sid, bool enabled, std::wstring& error)
{
	json response;
	return Call({ {"op", "set_enforcement"}, {"sid", Convert::ToString(sid)}, {"enabled", enabled} }, response, error);
}
