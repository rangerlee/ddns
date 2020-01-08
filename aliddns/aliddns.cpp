#include <iostream>
#include "aliddns.h"
#include "address.h"
#include <scarlet/infra/app/args.hpp>
#include <scarlet/utils/timer.hpp>
#include <scarlet/utils/event.hpp>
#include <scarlet/core/string.hpp>

int main(int argc, char* argv[]) {
	scarlet::args::value ak("access_key", 'k', "aliyun access key id", false);
	scarlet::args::value as("access_secret", 's', "aliyun access secret", false);
	scarlet::args::value rr("rr", 'r', "aliyun dns RR", false);
	scarlet::args::value domain("domain", 'd', "aliyun dns domain", false);
	scarlet::args::value interval("interval", 'i', "update interval, default 600 second");

	scarlet::args cmd;
	try {		
		cmd.add(ak).add(as).add(rr).add(domain).add(interval).parse(argc, argv);
	} catch (...) {
		std::cout << "alidns tool, v1.0" << std::endl;
		std::cout << "update alidns record with local's real public address" << std::endl;
		std::cout << "aliddns -d example.com -r test -k XXXXX -s YYYYY [-i 600]" << std::endl;
		std::cout << std::endl;
		std::cout << cmd.usage() << std::endl;
		return 0;
	}

	//alidns dns(ak.arg(), as.arg());
	//return dns.update(rr.arg(), domain.arg(), real_public_address());

	scarlet::timer meter;
	std::string pubaddr;
	scarlet::event_waiter waiter;
	alidns dns(ak.arg(), as.arg());
	int delay = 600;
	if (interval) delay = scarlet::convert_to_integer<int>(interval.arg());

	for (;;) {
		int next = (delay * 1.0 - meter.elapsed()) * 1000;
		waiter.wait(std::max<int>(0, next));
		meter.restart();

		std::string ip = real_public_address();
		if (ip == pubaddr || ip.empty()) continue;

		if (dns.update(rr.arg(), domain.arg(), ip)) {
			pubaddr = ip;
		} else {
			std::cerr << "update dns to " << ip << " faild" << std::endl;
		}
	}

	return 0;
}
