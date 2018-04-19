#ifndef _TYPES_H_
#define _TYPES_H_

#include <string>

#ifdef _WIN32
#pragma warning(disable:4200 4715)
#endif

#pragma pack(1)
struct ss5_select_request {
	unsigned char ver;
	unsigned char nmethods;
	unsigned char methods[0];
};

struct ss5_select_response {
	unsigned char ver;
	unsigned char method;
};

struct ss5_proxy_request {
	unsigned char ver;
	unsigned char cmd;
	unsigned char rsv;
	unsigned char atyp;
};

struct ss5_proxy_response {
	unsigned char ver;
	unsigned char rep;
	unsigned char rsv;
	unsigned char atyp;
};

struct ss5_porxy_address {
	std::string host;
	unsigned short port;
};
#pragma pack()

enum ss5_cmd { ss5_connect = 0x01, ss5_bind, ss5_udp_associate };

enum ss5_atyp { ss5_ipv4 = 0x01, ss5_fqdn = 0x03, ss5_ipv6 = 0x04 };

enum error_code {
	err_success = 0,
	err_no_more = -1,
	err_protocol = -2,
	err_auth = -3,
	err_unsupported = -4,
	err_cache_too_large = -5,
	err_unknown = -6
};
#endif
