#pragma once

#include "LocalCredentialStore.h"

#include <Windows.h>
#include <chrono>
#include <map>
#include <mutex>
#include <nlohmann/json_fwd.hpp>
#include <string>

class BrokerService
{
public:
	void Run(HANDLE stopEvent);
	bool ProcessRequest(HANDLE pipe, const std::string& request, std::string& response);

private:
	enum class SessionKind { Authentication, Registration, RemovalAuthorization };
	struct Session
	{
		SessionKind kind = SessionKind::Authentication;
		std::wstring callerSid;
		std::wstring targetSid;
		std::wstring username;
		std::string challenge;
		std::string rpId;
		std::string origin;
		std::string label;
		std::string credentialToRemove;
		std::chrono::steady_clock::time_point expiresAt;
	};

	struct Caller
	{
		std::wstring sid;
		bool isSystem = false;
		bool isElevatedAdmin = false;
	};

	bool GetCaller(HANDLE pipe, Caller& caller, std::string& error);
	bool Handle(const Caller& caller, nlohmann::json& request, nlohmann::json& response);
	bool VerifySessionAssertion(const Session& session, const nlohmann::json& assertion, std::string& error);
	nlohmann::json CreateAuthChallenge(const Session& session, const localfido::AccountRecord& account);
	nlohmann::json CreateRegistrationChallenge(const Session& session, const localfido::AccountRecord* account);
	std::string PutSession(Session session);
	bool TakeSession(const std::string& id, const Caller& caller, SessionKind expected, Session& session, std::string& error);

	localfido::LocalCredentialStore _store;
	std::mutex _sessionsMutex;
	std::map<std::string, Session> _sessions;
};
