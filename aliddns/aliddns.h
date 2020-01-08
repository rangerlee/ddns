#ifndef ALIDDNS_H_
#define ALIDDNS_H_
#include <string>
#include <map>
#include <rapidxml.hpp>
#include <scarlet/core/string.hpp>
#include <cryptlite/hmac.h>
#include <cryptlite/sha1.h>
#include <cryptlite/base64.h>
#include <scarlet/net/http_client.hpp>
#include <scarlet/utils/snowflake.hpp>

const char* alidns_uri = "https://alidns.aliyuncs.com/";

class alidns {
	struct record {
		std::string rr;
		std::string status;
		std::string value;
		std::string recordid;
		std::string type;
		std::string weight;
		std::string domainname;
		std::string locked;
		std::string line;
		std::string ttl;
	};

public:
	alidns(const std::string& access_key, const std::string& access_secret) 
	: access_key_(access_key), access_secret_(access_secret) {	
	}

	bool update(const std::string& rr, const std::string& domain, const std::string& value, const std::string& type = "A") {
		if (rr.empty() || domain.empty() || value.empty() || type.empty()) return false;
		auto rs = describe_domain_records(domain);
		if (rs.find(rr) == rs.end()) return false;
		struct record r = rs[rr];
		if (r.domainname == domain && r.value == value && r.type == type) return true;

		std::map<std::string, std::string> param;
		param["AccessKeyId"] = access_key_;
		param["Format"] = "XML";
		param["Version"] = "2015-01-09";
		param["SignatureMethod"] = "HMAC-SHA1";
		param["SignatureVersion"] = "1.0";
		param["RR"] = rr;
		param["Type"] = type;
		param["Value"] = value;
		param["RecordId"] = r.recordid;
		param["Action"] = "UpdateDomainRecord";
		param["Timestamp"] = utc();
		param["SignatureNonce"] = scarlet::format("%lld", rand_.generate());
		param["Signature"] = prepare_signature(param);
		std::map<std::string, std::string> param_encoded;
		for (auto it = param.begin(); it != param.end(); it++) {
			param_encoded[percent_encode(it->first)] = percent_encode(it->second);
		}

		std::string uri = scarlet::format("%s?%s", alidns_uri, scarlet::join(param_encoded, '=', '&').c_str());
		scarlet::http_client http;
		auto ret = http.get(uri);
		if (std::get<0>(ret) && std::get<1>(ret) == 200 && std::get<2>(ret)) {
			rapidxml::xml_document<> doc;
			doc.parse<0>((char*)std::get<2>(ret)->data());
			rapidxml::xml_node<>* root = doc.first_node("UpdateDomainRecordResponse");
			if (!root) return false;

			rapidxml::xml_node<>* id = root->first_node("RecordId");
			if (!id) return false;
		}

		return false;
	}

private:
	std::map<std::string, struct record> describe_domain_records(const std::string& domain) {
		std::map<std::string, std::string> param;
		param["AccessKeyId"] = access_key_;
		param["Format"] = "XML";
		param["Version"] = "2015-01-09";
		param["SignatureMethod"] = "HMAC-SHA1";
		param["SignatureVersion"] = "1.0";
		param["DomainName"] = domain;
		param["Action"] = "DescribeDomainRecords";
		param["Timestamp"] = utc();
		param["SignatureNonce"] = scarlet::format("%lld", rand_.generate());
		param["Signature"] = prepare_signature(param);
		std::map<std::string, std::string> param_encoded;
		for (auto it = param.begin(); it != param.end(); it++) {
			param_encoded[percent_encode(it->first)] = percent_encode(it->second);
		}

		std::string uri = scarlet::format("%s?%s", alidns_uri, scarlet::join(param_encoded, '=', '&').c_str());
		std::map<std::string, struct record> res;
		scarlet::http_client http;
		auto ret = http.get(uri);
		if (std::get<0>(ret) && std::get<1>(ret) == 200 && std::get<2>(ret)) {
			rapidxml::xml_document<> doc;
			doc.parse<0>((char*)std::get<2>(ret)->data());
			rapidxml::xml_node<>* root = doc.first_node("DescribeDomainRecordsResponse");
			if (root) {
				rapidxml::xml_node<>* rs = root->first_node("DomainRecords");
				for (rapidxml::xml_node<>* r = rs->first_node("Record"); r; r = r->next_sibling()) {
					struct record one;
					one.rr = r->first_node("RR")->value();
					one.status = r->first_node("Status")->value();
					one.recordid = r->first_node("RecordId")->value();
					one.value = r->first_node("Value")->value();
					one.type = r->first_node("Type")->value();
					one.domainname = r->first_node("DomainName")->value();
					one.locked = r->first_node("Locked")->value();
					one.line = r->first_node("Line")->value();
					one.ttl = r->first_node("TTL")->value();
					one.weight = r->first_node("Weight") ? r->first_node("Weight")->value() : "";
					res[one.rr] = one;
				}
			}
		}

		return res;

		/*
		<DescribeDomainRecordsResponse>
		  ...
		  <DomainRecords>
			<Record>
			  <RR>home</RR>
			  <Status>ENABLE</Status>
			  <Value>121.42.182.33</Value>
			  <RecordId>18828997325970432</RecordId>
			  <Type>A</Type>
			  <DomainName>xilixili.net</DomainName>
			  <Locked>false</Locked>
			  <Line>default</Line>
			  <TTL>600</TTL>
			</Record>
		*/		
	}

private:
	std::string prepare_signature(const std::map<std::string,std::string>& param) {
		std::string str = "GET&%2F&";
		std::map<std::string, std::string> param_encoded;
		for (auto it = param.begin(); it != param.end(); it++) {
			param_encoded[percent_encode(it->first)] = percent_encode(it->second);
		}

		str += percent_encode(scarlet::join(param_encoded, "=", "&"));
		uint8_t digest[20] = { 0 };
		cryptlite::hmac<cryptlite::sha1>::calc(str, access_secret_ + "&", digest);
		return cryptlite::base64::encode_from_array(digest, 20);
	}

	std::string percent_encode(const std::string& data) {		
		std::string str = scarlet::url_escape(data);
		// + => %20 * => %2A %7E => ~
		scarlet::replace(str, "+", "%20", false);
		scarlet::replace(str, "*", "%2A", false);
		scarlet::replace(str, "%7E", "~", false);
		return str;
	}

	std::string utc() {
		time_t now;
		struct tm *timenow;
		now = time(&now);
		timenow = gmtime(&now);
		std::string res = scarlet::format("%d-%02d-%02dT%02d:%02d:%02dZ", 
			timenow->tm_year + 1900,
			timenow->tm_mon + 1,
			timenow->tm_mday,
			timenow->tm_hour,
			timenow->tm_min,
			timenow->tm_sec);
		return res;
	}

private:
	std::string access_key_;
	std::string access_secret_;
	scarlet::snowflake rand_;
};

#endif
