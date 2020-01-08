#ifndef ADDRESS_H_
#define ADDRESS_H_

#include <string>
#include <vector>
#include <scarlet/net/http_client.hpp>
#include <scarlet/core/string.hpp>

std::string real_public_address() {
	// thoes api return ip address
	std::vector<std::string> api = {
		"https://ifconfig.co/ip",
		"http://ipinfo.io/ip"		 
	};

	for (size_t i = 0; i < api.size(); i++) {
		scarlet::http_client cli;
		auto res = cli.get(api[i]);
		if (std::get<0>(res) && std::get<1>(res) == 200 && std::get<2>(res)) {
			if (!std::get<2>(res)->empty()) {
				return scarlet::trim(*std::get<2>(res));
			}
		}
	}

	return std::string();
}

#endif
