#include "BrokerService.h"

#include "Convert.h"
#include "FidoVerifier.h"
#include "LocalAccount.h"
#include "LocalFidoTypes.h"

#include <Windows.h>
#include <Sddl.h>
#include <bcrypt.h>
#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <iterator>
#include <nlohmann/json.hpp>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#pragma comment(lib, "Bcrypt.lib")

using json = nlohmann::json;

namespace
{
	constexpr auto kSessionLifetime = std::chrono::seconds(120);
	constexpr size_t kMaximumCredentialsPerAccount = 64;
	constexpr size_t kMaximumSessions = 256;
	constexpr size_t kMaximumSessionsPerCaller = 32;
	constexpr DWORD kPipeIoTimeoutMs = 5000;

	std::string RandomId(size_t bytes)
	{
		std::vector<unsigned char> data(bytes);
		if (BCryptGenRandom(nullptr, data.data(), static_cast<ULONG>(data.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) return {};
		return Convert::Base64URLEncode(data);
	}

	std::string UtcNow()
	{
		SYSTEMTIME time{};
		GetSystemTime(&time);
		char value[32]{};
		sprintf_s(value, "%04u-%02u-%02uT%02u:%02u:%02uZ", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
		return value;
	}

	std::wstring ExtractPassword(json& request)
	{
		auto& encoded = request.at("password").get_ref<std::string&>();
		try
		{
			std::wstring result = Convert::ToWString(encoded);
			if (!encoded.empty()) SecureZeroMemory(encoded.data(), encoded.size());
			encoded.clear();
			return result;
		}
		catch (...)
		{
			if (!encoded.empty()) SecureZeroMemory(encoded.data(), encoded.size());
			encoded.clear();
			throw;
		}
	}

	void ClearRequestPassword(json& request) noexcept
	{
		try
		{
			if (!request.contains("password") || !request["password"].is_string()) return;
			auto& password = request["password"].get_ref<std::string&>();
			if (!password.empty()) SecureZeroMemory(password.data(), password.size());
			password.clear();
		}
		catch (...) {}
	}

	std::string CheckedLabel(const json& request, const char* name, const std::string& fallback)
	{
		std::string label = request.value(name, fallback);
		if (label.empty()) label = fallback;
		if (label.size() > 128 || std::any_of(label.begin(), label.end(), [](unsigned char value) { return value < 0x20 || value == 0x7f; }))
			throw std::runtime_error("invalid security-key label");
		return label;
	}

	json CredentialPublicJson(const localfido::CredentialRecord& record)
	{
		return {
			{"credentialId", record.credentialId}, {"algorithm", record.algorithm}, {"aaguid", record.aaguid},
			{"label", record.label}, {"createdAt", record.createdAt}, {"signCount", record.signCount}
		};
	}

	FIDOSignResponse AssertionFromJson(const json& value)
	{
		FIDOSignResponse response;
		response.clientdata = value.at("clientData").get<std::string>();
		for (const auto& item : value.at("assertions"))
		{
			FIDOAssertionData assertion;
			assertion.credentialid = item.at("credentialId").get<std::string>();
			assertion.authenticatordata = item.at("authenticatorData").get<std::string>();
			assertion.signaturedata = item.at("signature").get<std::string>();
			assertion.userHandle = item.value("userHandle", "");
			response.assertions.push_back(std::move(assertion));
		}
		return response;
	}

	bool TokenSid(HANDLE token, std::wstring& sid)
	{
		DWORD size = 0;
		GetTokenInformation(token, TokenUser, nullptr, 0, &size);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
		std::vector<BYTE> buffer(size);
		if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) return false;
		LPWSTR value = nullptr;
		if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &value)) return false;
		sid.assign(value);
		LocalFree(value);
		return true;
	}

	bool TokenIsElevatedAdmin(HANDLE token)
	{
		TOKEN_ELEVATION elevation{};
		DWORD size = 0;
		if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size) || !elevation.TokenIsElevated) return false;
		BYTE adminSidBuffer[SECURITY_MAX_SID_SIZE]{};
		DWORD adminSidSize = sizeof(adminSidBuffer);
		if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSidBuffer, &adminSidSize)) return false;
		BOOL member = FALSE;
		return CheckTokenMembership(token, adminSidBuffer, &member) && member;
	}

	bool IsSameSid(const std::wstring& left, const std::wstring& right)
	{
		return _wcsicmp(left.c_str(), right.c_str()) == 0;
	}

	bool HasConflictingCredentialProviderFilter(std::wstring& conflictingClsid, DWORD& error)
	{
		error = ERROR_SUCCESS;
		constexpr wchar_t kFilterRegistry[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters";
		constexpr wchar_t kOurFilter[] = L"{54B25B17-C7AE-4C2B-B3C4-E3B29A73D9B1}";
		HKEY key = nullptr;
		const LONG openStatus = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kFilterRegistry, 0,
			KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY, &key);
		if (openStatus == ERROR_FILE_NOT_FOUND) return false;
		if (openStatus != ERROR_SUCCESS) { error = openStatus; return false; }
		wchar_t name[128]{};
		for (DWORD index = 0;; ++index)
		{
			DWORD length = ARRAYSIZE(name);
			const LONG status = RegEnumKeyExW(key, index, name, &length, nullptr, nullptr, nullptr, nullptr);
			if (status == ERROR_NO_MORE_ITEMS) break;
			if (status != ERROR_SUCCESS)
			{
				error = status;
				RegCloseKey(key);
				return false;
			}
			if (status == ERROR_SUCCESS && _wcsicmp(name, kOurFilter) != 0)
			{
				conflictingClsid.assign(name, length);
				RegCloseKey(key);
				return true;
			}
		}
		RegCloseKey(key);
		return false;
	}

	bool AwaitOverlapped(HANDLE pipe, OVERLAPPED& operation, HANDLE stopEvent, DWORD timeout, DWORD& transferred)
	{
		const HANDLE waits[] = { stopEvent, operation.hEvent };
		const DWORD waitResult = WaitForMultipleObjects(ARRAYSIZE(waits), waits, FALSE, timeout);
		if (waitResult == WAIT_OBJECT_0 + 1)
			return GetOverlappedResult(pipe, &operation, &transferred, FALSE) == TRUE;

		CancelIoEx(pipe, &operation);
		WaitForSingleObject(operation.hEvent, INFINITE);
		DWORD ignored = 0;
		GetOverlappedResult(pipe, &operation, &ignored, FALSE);
		SetLastError(waitResult == WAIT_TIMEOUT ? ERROR_SEM_TIMEOUT : ERROR_OPERATION_ABORTED);
		return false;
	}

	bool ConnectWithStop(HANDLE pipe, HANDLE stopEvent)
	{
		OVERLAPPED operation{};
		operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!operation.hEvent) return false;
		bool connected = false;
		if (ConnectNamedPipe(pipe, &operation)) connected = true;
		else
		{
			const DWORD connectError = GetLastError();
			if (connectError == ERROR_PIPE_CONNECTED) connected = true;
			else if (connectError == ERROR_IO_PENDING)
			{
				DWORD ignored = 0;
				connected = AwaitOverlapped(pipe, operation, stopEvent, INFINITE, ignored);
			}
		}
		CloseHandle(operation.hEvent);
		return connected;
	}

	bool ReadWithDeadline(HANDLE pipe, HANDLE stopEvent, void* buffer, DWORD size, DWORD& read)
	{
		read = 0;
		OVERLAPPED operation{};
		operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!operation.hEvent) return false;
		bool ok = false;
		if (ReadFile(pipe, buffer, size, nullptr, &operation))
			ok = GetOverlappedResult(pipe, &operation, &read, FALSE) == TRUE;
		else if (GetLastError() == ERROR_IO_PENDING)
			ok = AwaitOverlapped(pipe, operation, stopEvent, kPipeIoTimeoutMs, read);
		CloseHandle(operation.hEvent);
		return ok;
	}

	bool WriteWithDeadline(HANDLE pipe, HANDLE stopEvent, const void* buffer, DWORD size)
	{
		OVERLAPPED operation{};
		operation.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
		if (!operation.hEvent) return false;
		DWORD written = 0;
		bool ok = false;
		if (WriteFile(pipe, buffer, size, nullptr, &operation))
			ok = GetOverlappedResult(pipe, &operation, &written, FALSE) == TRUE;
		else if (GetLastError() == ERROR_IO_PENDING)
			ok = AwaitOverlapped(pipe, operation, stopEvent, kPipeIoTimeoutMs, written);
		CloseHandle(operation.hEvent);
		return ok && written == size;
	}
}

void BrokerService::Run(HANDLE stopEvent)
{
	DWORD startupError = ERROR_SUCCESS;
	if (!_store.RefreshLocalAccounts(&startupError)) return;
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)", SDDL_REVISION_1, &descriptor, nullptr)) return;
	SECURITY_ATTRIBUTES attributes{ sizeof(attributes), descriptor, FALSE };
	HANDLE pipe = CreateNamedPipeW(
		localfido::kBrokerPipeName,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		localfido::kMaxBrokerMessageBytes,
		localfido::kMaxBrokerMessageBytes,
		1000,
		&attributes);
	if (pipe == INVALID_HANDLE_VALUE)
	{
		LocalFree(descriptor);
		return;
	}
	while (WaitForSingleObject(stopEvent, 0) == WAIT_TIMEOUT)
	{
		if (ConnectWithStop(pipe, stopEvent))
		{
			std::vector<char> buffer(localfido::kMaxBrokerMessageBytes);
			DWORD read = 0;
			if (ReadWithDeadline(pipe, stopEvent, buffer.data(), static_cast<DWORD>(buffer.size()), read) && read > 0)
			{
				std::string response;
				std::string request(buffer.data(), read);
				ProcessRequest(pipe, request, response);
				SecureZeroMemory(request.data(), request.size());
				if (response.size() > localfido::kMaxBrokerMessageBytes)
					response = R"({"ok":false,"error":"Broker response is too large"})";
				if (WriteWithDeadline(pipe, stopEvent, response.data(), static_cast<DWORD>(response.size())))
				{
					// The acknowledgement proves the client consumed the response before
					// DisconnectNamedPipe discards any unread pipe data.
					char acknowledgement = 0;
					DWORD acknowledgementSize = 0;
					(void)ReadWithDeadline(pipe, stopEvent, &acknowledgement, 1, acknowledgementSize);
				}
			}
			DisconnectNamedPipe(pipe);
		}
	}
	CloseHandle(pipe);
	LocalFree(descriptor);
}

bool BrokerService::GetCaller(HANDLE pipe, Caller& caller, std::string& error)
{
	if (!ImpersonateNamedPipeClient(pipe)) { error = "unable to identify pipe caller"; return false; }
	HANDLE token = nullptr;
	const bool opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token) == TRUE;
	if (!opened)
	{
		error = "unable to open pipe caller token";
		RevertToSelf();
		return false;
	}
	const bool found = TokenSid(token, caller.sid);
	caller.isSystem = found && localfido::IsLocalSystemSid(caller.sid);
	caller.isElevatedAdmin = caller.isSystem || TokenIsElevatedAdmin(token);
	CloseHandle(token);
	RevertToSelf();
	if (!found) error = "unable to resolve pipe caller SID";
	return found;
}

bool BrokerService::ProcessRequest(HANDLE pipe, const std::string& input, std::string& output)
{
	json response = { {"ok", false} };
	json request;
	try
	{
		if (input.empty() || input.size() > localfido::kMaxBrokerMessageBytes) throw std::runtime_error("invalid request size");
		request = json::parse(input);
		if (request.value("version", 0u) != localfido::kBrokerProtocolVersion) throw std::runtime_error("unsupported Broker protocol version");
		Caller caller;
		std::string error;
		if (!GetCaller(pipe, caller, error)) throw std::runtime_error(error);
		Handle(caller, request, response);
	}
	catch (const std::exception& exception)
	{
		response = { {"ok", false}, {"error", exception.what()} };
	}
	ClearRequestPassword(request);
	output = response.dump();
	return response.value("ok", false);
}

std::string BrokerService::PutSession(Session session)
{
	if (session.challenge.empty() || session.rpId.empty() || session.origin.empty())
		throw std::runtime_error("unable to create cryptographic session");
	session.expiresAt = std::chrono::steady_clock::now() + kSessionLifetime;
	std::lock_guard<std::mutex> lock(_sessionsMutex);
	for (auto it = _sessions.begin(); it != _sessions.end();)
	{
		if (it->second.expiresAt <= std::chrono::steady_clock::now()) it = _sessions.erase(it); else ++it;
	}
	if (_sessions.size() >= kMaximumSessions ||
		std::count_if(_sessions.begin(), _sessions.end(), [&](const auto& value)
			{ return IsSameSid(value.second.callerSid, session.callerSid); }) >= kMaximumSessionsPerCaller)
		throw std::runtime_error("too many active Broker sessions");
	for (unsigned int attempt = 0; attempt < 4; ++attempt)
	{
		const std::string id = RandomId(24);
		if (!id.empty() && _sessions.emplace(id, session).second) return id;
	}
	throw std::runtime_error("unable to allocate unique Broker session");
}

bool BrokerService::TakeSession(const std::string& id, const Caller& caller, SessionKind expected, Session& session, std::string& error)
{
	if (id.size() != 32) { error = "invalid session identifier"; return false; }
	std::lock_guard<std::mutex> lock(_sessionsMutex);
	const auto it = _sessions.find(id);
	if (it == _sessions.end()) { error = "unknown or already-used session"; return false; }
	session = it->second;
	_sessions.erase(it); // consume before validation to prevent replay
	if (session.expiresAt <= std::chrono::steady_clock::now()) { error = "session expired"; return false; }
	if (session.kind != expected) { error = "wrong session type"; return false; }
	if (!caller.isSystem && !IsSameSid(caller.sid, session.callerSid)) { error = "session belongs to another user"; return false; }
	return true;
}

json BrokerService::CreateAuthChallenge(const Session& session, const localfido::AccountRecord& account)
{
	json ids = json::array();
	for (const auto& credential : account.credentials) ids.push_back(credential.credentialId);
	return {
		{"enforced", true}, {"rpId", session.rpId}, {"origin", session.origin},
		{"challenge", session.challenge}, {"credentialIds", ids}
	};
}

json BrokerService::CreateRegistrationChallenge(const Session& session, const localfido::AccountRecord* account)
{
	json excludes = json::array();
	if (account) for (const auto& credential : account->credentials) excludes.push_back(credential.credentialId);
	const std::string userId = RandomId(32);
	if (userId.empty()) throw std::runtime_error("unable to generate registration user handle");
	return {
		{"sessionId", ""}, {"rpId", session.rpId}, {"origin", session.origin},
		{"challenge", session.challenge}, {"userId", userId}, {"excludeCredentials", excludes}
	};
}

bool BrokerService::VerifySessionAssertion(const Session& session, const json& assertionValue, std::string& error)
{
	auto account = _store.FindAccount(session.targetSid);
	if (!account || account->credentials.empty()) { error = "account has no registered credentials"; return false; }
	const FIDOSignResponse assertion = AssertionFromJson(assertionValue);
	if (assertion.assertions.size() != 1) { error = "exactly one assertion is required"; return false; }
	const auto record = std::find_if(account->credentials.begin(), account->credentials.end(), [&](const localfido::CredentialRecord& item)
		{ return item.credentialId == assertion.assertions.front().credentialid; });
	if (record == account->credentials.end()) { error = "credential is not registered for this SID"; return false; }
	uint32_t counter = 0;
	if (!localfido::FidoVerifier::VerifyAssertion(*record, session.challenge, session.rpId, session.origin, assertion, counter, error)) return false;
	record->signCount = counter;
	DWORD storeError = ERROR_SUCCESS;
	if (!_store.UpsertAccount(*account, &storeError)) { error = "unable to update credential counter"; return false; }
	return true;
}

bool BrokerService::Handle(const Caller& caller, json& request, json& response)
{
	DWORD refreshError = ERROR_SUCCESS;
	if (!_store.RefreshLocalAccounts(&refreshError)) throw std::runtime_error("unable to refresh local account state");
	const std::string operation = request.value("op", "");
	if (operation == "status")
	{
		const std::wstring sid = Convert::ToWString(request.at("sid").get<std::string>());
		if (!caller.isSystem && !caller.isElevatedAdmin && !IsSameSid(caller.sid, sid)) throw std::runtime_error("access denied");
		auto account = _store.FindAccount(sid);
		response = { {"ok", true}, {"found", account.has_value()}, {"enforced", account && account->enforced} };
		if (account)
		{
			response["username"] = Convert::ToString(account->username);
			response["credentials"] = json::array();
			for (const auto& credential : account->credentials) response["credentials"].push_back(CredentialPublicJson(credential));
		}
		return true;
	}

	localfido::Vault vault;
	DWORD storeError = ERROR_SUCCESS;
	if (!_store.LoadOrCreate(vault, &storeError)) throw std::runtime_error("credential vault unavailable");
	const std::string origin = "https://" + vault.rpId;

	if (operation == "begin_auth")
	{
		const std::wstring sid = Convert::ToWString(request.at("sid").get<std::string>());
		if (!caller.isSystem && !IsSameSid(caller.sid, sid)) throw std::runtime_error("access denied");
		auto account = _store.FindAccount(sid);
		if (!account || !account->enforced)
		{
			if (localfido::LocalCredentialStore::IsSidEnforced(sid))
				throw std::runtime_error("MFA policy state is inconsistent; authentication is blocked");
			response = { {"ok", true}, {"enforced", false} };
			return true;
		}
		if (account->credentials.size() < 2) throw std::runtime_error("enforced account does not have two credentials");
		Session session;
		session.kind = SessionKind::Authentication;
		session.callerSid = caller.sid;
		session.targetSid = sid;
		session.challenge = RandomId(32);
		session.rpId = vault.rpId;
		session.origin = origin;
		const std::string id = PutSession(session);
		response = CreateAuthChallenge(session, *account);
		response["sessionId"] = id;
		response["ok"] = true;
		return true;
	}

	if (operation == "finish_auth")
	{
		Session session;
		std::string error;
		if (!TakeSession(request.at("sessionId").get<std::string>(), caller, SessionKind::Authentication, session, error)) throw std::runtime_error(error);
		if (!VerifySessionAssertion(session, request.at("assertion"), error)) throw std::runtime_error(error);
		response = { {"ok", true} };
		return true;
	}

	if (operation == "begin_test")
	{
		const std::wstring sid = Convert::ToWString(request.at("sid").get<std::string>());
		if (!caller.isSystem && !IsSameSid(caller.sid, sid)) throw std::runtime_error("access denied");
		auto account = _store.FindAccount(sid);
		if (!account || account->credentials.empty()) throw std::runtime_error("account has no registered credentials");
		Session session;
		session.kind = SessionKind::Authentication;
		session.callerSid = caller.sid;
		session.targetSid = sid;
		session.challenge = RandomId(32);
		session.rpId = vault.rpId;
		session.origin = origin;
		const std::string id = PutSession(session);
		response = CreateAuthChallenge(session, *account);
		response["sessionId"] = id;
		response["ok"] = true;
		return true;
	}

	if (operation == "begin_registration")
	{
		const std::wstring sid = Convert::ToWString(request.at("sid").get<std::string>());
		const std::wstring username = Convert::ToWString(request.at("username").get<std::string>());
		std::wstring password = ExtractPassword(request);
		if (!IsSameSid(caller.sid, sid)) { SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t)); throw std::runtime_error("registration is limited to the current user"); }
		std::wstring resolvedName, computer, resolvedSid;
		if (!localfido::ResolveLocalAccount(username, resolvedName, computer, resolvedSid) || !IsSameSid(sid, resolvedSid))
		{
			SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
			throw std::runtime_error("target is not the current local account");
		}
		const bool passwordOk = localfido::ValidateLocalPassword(resolvedName, password);
		SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
		if (!passwordOk) throw std::runtime_error("Windows password validation failed");

		auto account = _store.FindAccount(sid);
		if (account && account->credentials.size() >= kMaximumCredentialsPerAccount)
			throw std::runtime_error("maximum registered security-key count reached");
		Session session;
		session.callerSid = caller.sid;
		session.targetSid = sid;
		session.username = resolvedName;
		session.label = CheckedLabel(request, "label", "Security key");
		session.rpId = vault.rpId;
		session.origin = origin;
		session.challenge = RandomId(32);
		if (account && !account->credentials.empty())
		{
			session.kind = SessionKind::RegistrationAuthorization;
			const std::string id = PutSession(session);
			json authorization = CreateAuthChallenge(session, *account);
			authorization["sessionId"] = id;
			response = { {"ok", true}, {"authorizationRequired", true}, {"authorization", authorization} };
		}
		else
		{
			session.kind = SessionKind::Registration;
			const std::string id = PutSession(session);
			json registration = CreateRegistrationChallenge(session, account ? &*account : nullptr);
			registration["sessionId"] = id;
			response = { {"ok", true}, {"authorizationRequired", false}, {"registration", registration} };
		}
		return true;
	}

	if (operation == "authorize_registration")
	{
		Session authorization;
		std::string error;
		if (!TakeSession(request.at("sessionId").get<std::string>(), caller, SessionKind::RegistrationAuthorization, authorization, error)) throw std::runtime_error(error);
		if (!VerifySessionAssertion(authorization, request.at("assertion"), error)) throw std::runtime_error(error);
		auto account = _store.FindAccount(authorization.targetSid);
		authorization.kind = SessionKind::Registration;
		authorization.challenge = RandomId(32);
		const std::string id = PutSession(authorization);
		json registration = CreateRegistrationChallenge(authorization, account ? &*account : nullptr);
		registration["sessionId"] = id;
		response = { {"ok", true}, {"registration", registration} };
		return true;
	}

	if (operation == "commit_registration")
	{
		Session session;
		std::string error;
		if (!TakeSession(request.at("sessionId").get<std::string>(), caller, SessionKind::Registration, session, error)) throw std::runtime_error(error);
		localfido::RegistrationResult registration;
		if (!localfido::FidoVerifier::VerifyRegistration(
			session.challenge, session.rpId, session.origin,
			request.at("attestationObject").get<std::string>(), request.at("clientDataJson").get<std::string>(), registration, error))
			throw std::runtime_error(error);
		localfido::Vault current;
		if (!_store.LoadOrCreate(current)) throw std::runtime_error("credential vault unavailable");
		for (const auto& account : current.accounts)
			for (const auto& credential : account.credentials)
				if (credential.credentialId == registration.credentialId) throw std::runtime_error("credential is already registered");
		localfido::CredentialRecord record;
		record.credentialId = registration.credentialId;
		record.cosePublicKey = registration.cosePublicKey;
		record.algorithm = registration.algorithm;
		record.aaguid = registration.aaguid;
		record.label = session.label;
		record.createdAt = UtcNow();
		record.signCount = registration.signCount;
		session.kind = SessionKind::RegistrationProof;
		session.challenge = RandomId(32);
		session.pendingCredential = record;
		const std::string proofId = PutSession(session);
		localfido::AccountRecord proofAccount;
		proofAccount.credentials.push_back(record);
		json proof = CreateAuthChallenge(session, proofAccount);
		proof["sessionId"] = proofId;
		response = { {"ok", true}, {"proof", proof} };
		return true;
	}

	if (operation == "finish_registration")
	{
		Session session;
		std::string error;
		if (!TakeSession(request.at("sessionId").get<std::string>(), caller, SessionKind::RegistrationProof, session, error)) throw std::runtime_error(error);
		const FIDOSignResponse assertion = AssertionFromJson(request.at("assertion"));
		uint32_t counter = 0;
		if (!localfido::FidoVerifier::VerifyAssertion(session.pendingCredential, session.challenge, session.rpId, session.origin, assertion, counter, error))
			throw std::runtime_error(error);
		session.pendingCredential.signCount = counter;
		localfido::Vault current;
		if (!_store.LoadOrCreate(current)) throw std::runtime_error("credential vault unavailable");
		for (const auto& account : current.accounts)
			for (const auto& credential : account.credentials)
				if (credential.credentialId == session.pendingCredential.credentialId) throw std::runtime_error("credential is already registered");
		auto account = std::find_if(current.accounts.begin(), current.accounts.end(), [&](const localfido::AccountRecord& value) { return IsSameSid(value.sid, session.targetSid); });
		if (account == current.accounts.end())
		{
			localfido::AccountRecord created;
			created.sid = session.targetSid;
			created.username = session.username;
			current.accounts.push_back(std::move(created));
			account = std::prev(current.accounts.end());
		}
		else
		{
			account->username = session.username;
		}
		account->credentials.push_back(std::move(session.pendingCredential));
		if (!_store.Save(current)) throw std::runtime_error("unable to save registered credential");
		response = { {"ok", true}, {"credentialCount", account->credentials.size()} };
		return true;
	}

	if (operation == "begin_remove")
	{
		const std::wstring sid = Convert::ToWString(request.at("sid").get<std::string>());
		const std::wstring username = Convert::ToWString(request.at("username").get<std::string>());
		std::wstring password = ExtractPassword(request);
		if (!IsSameSid(caller.sid, sid)) { SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t)); throw std::runtime_error("access denied"); }
		std::wstring resolvedName, computer, resolvedSid;
		const bool localAccount = localfido::ResolveLocalAccount(username, resolvedName, computer, resolvedSid) && IsSameSid(sid, resolvedSid);
		const bool passwordOk = localAccount && localfido::ValidateLocalPassword(resolvedName, password);
		SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
		if (!passwordOk) throw std::runtime_error("Windows password validation failed");
		auto account = _store.FindAccount(sid);
		if (!account || account->credentials.empty()) throw std::runtime_error("account has no registered credentials");
		if (account->enforced && account->credentials.size() <= 2) throw std::runtime_error("enforced accounts must retain at least two credentials");
		const std::string credentialId = request.at("credentialId").get<std::string>();
		if (std::none_of(account->credentials.begin(), account->credentials.end(), [&](const localfido::CredentialRecord& item) { return item.credentialId == credentialId; }))
			throw std::runtime_error("credential is not registered for this account");
		Session session;
		session.kind = SessionKind::RemovalAuthorization;
		session.callerSid = caller.sid;
		session.targetSid = sid;
		session.username = resolvedName;
		session.credentialToRemove = credentialId;
		session.challenge = RandomId(32);
		session.rpId = vault.rpId;
		session.origin = origin;
		const std::string id = PutSession(session);
		json authorization = CreateAuthChallenge(session, *account);
		authorization["sessionId"] = id;
		response = { {"ok", true}, {"authorization", authorization} };
		return true;
	}

	if (operation == "finish_remove")
	{
		Session session;
		std::string error;
		if (!TakeSession(request.at("sessionId").get<std::string>(), caller, SessionKind::RemovalAuthorization, session, error)) throw std::runtime_error(error);
		if (!VerifySessionAssertion(session, request.at("assertion"), error)) throw std::runtime_error(error);
		if (!_store.RemoveCredential(session.targetSid, session.credentialToRemove, &storeError)) throw std::runtime_error("unable to remove credential");
		response = { {"ok", true} };
		return true;
	}

	if (operation == "set_enforcement")
	{
		if (!caller.isElevatedAdmin) throw std::runtime_error("administrator elevation is required");
		const std::wstring sid = Convert::ToWString(request.at("sid").get<std::string>());
		const bool enabled = request.at("enabled").get<bool>();
		if (enabled)
		{
			std::wstring conflict;
			DWORD filterError = ERROR_SUCCESS;
			if (HasConflictingCredentialProviderFilter(conflict, filterError))
				throw std::runtime_error("another global Credential Provider Filter is registered: " + Convert::ToString(conflict));
			if (filterError != ERROR_SUCCESS)
				throw std::runtime_error("unable to inspect installed Credential Provider Filters");
		}
		if (!_store.SetEnforced(sid, enabled, &storeError)) throw std::runtime_error("unable to change enforcement policy (two distinct keys are required before enabling)");
		response = { {"ok", true} };
		return true;
	}

	throw std::runtime_error("unsupported Broker operation");
}
