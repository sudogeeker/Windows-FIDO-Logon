#include "BrokerService.h"
#include "LocalFidoTypes.h"

#include <nlohmann/json.hpp>
#include <iostream>
#include <stdexcept>
#include <string>

namespace
{
	void Require(bool value, const char* message)
	{
		if (!value) throw std::runtime_error(message);
	}

	void RequireRejected(BrokerService& service, const std::string& input, const char* expected)
	{
		std::string output;
		Require(!service.ProcessRequest(INVALID_HANDLE_VALUE, input, output), "malformed Broker request was accepted");
		Require(output.size() <= localfido::kMaxBrokerMessageBytes, "Broker error response exceeded protocol limit");
		const auto response = nlohmann::json::parse(output);
		Require(!response.value("ok", true), "Broker rejection omitted ok=false");
		Require(response.value("error", "").find(expected) != std::string::npos, "Broker rejection reason mismatch");
	}
}

int main()
{
	try
	{
		BrokerService service;
		RequireRejected(service, "", "invalid request size");
		RequireRejected(service, "{", "parse error");
		RequireRejected(service, R"({"version":999,"op":"status"})", "unsupported Broker protocol version");
		RequireRejected(service, R"({"version":1,"op":"status"})", "identify pipe caller");
		RequireRejected(service, std::string(localfido::kMaxBrokerMessageBytes + 1, 'x'), "invalid request size");
		std::cout << "BrokerProtocolTests passed\n";
		return 0;
	}
	catch (const std::exception& exception)
	{
		std::cerr << "BrokerProtocolTests failed: " << exception.what() << "\n";
		return 1;
	}
}
