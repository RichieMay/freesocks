#ifndef _TABLE_REPEATER_H_
#define _TABLE_REPEATER_H_

#include "repeater.h"
#include <boost/date_time.hpp>
#include <boost/thread/mutex.hpp>

class table_repeater : public repeater
{
private:
	boost::mutex lock_;
	std::string proxy_host_;
	boost::uint16_t proxy_port_;
	unsigned char* encrypt_table_;
	unsigned char* decrypt_table_;

public:

	table_repeater(const std::string& proxy_host, boost::uint16_t proxy_port, const std::string& secret)
		: proxy_host_(proxy_host), proxy_port_(proxy_port)
	{
		static unsigned char encrypt_table[256] = {
			0x37, 0xc5, 0xd6, 0x21, 0x8e, 0xee, 0xae, 0x1c, 0xcf, 0x06, 0xed, 0xc6, 0xec, 0x59, 0x09, 0x16, 0xe4, 0x22, 0xb0, 0x73, 0x79, 0x83, 0xc2, 0xcc, 0x9d, 0x4f, 0x23, 0xd5, 0x2d, 0xaa, 0x2a, 0x78,
			0x5d, 0x45, 0x32, 0x7e, 0x9b, 0x0a, 0x84, 0x57, 0x00, 0x9e, 0xeb, 0x88, 0xe7, 0x17, 0x9a, 0xa6, 0x3c, 0x33, 0x77, 0x34, 0xe2, 0x7d, 0xca, 0x7f, 0x27, 0xd3, 0xce, 0xf0, 0x1b, 0x63, 0x43, 0xad,
			0xdf, 0x3f, 0xb7, 0xff, 0xb4, 0xf8, 0x0e, 0x35, 0x9c, 0xb8, 0x50, 0x68, 0xda, 0xe0, 0x82, 0x39, 0x72, 0x66, 0x30, 0x87, 0xe6, 0x19, 0x52, 0x2e, 0x61, 0xb1, 0xcd, 0xe1, 0xdd, 0x4c, 0x38, 0xdc,
			0x62, 0xe5, 0x93, 0x5b, 0x0b, 0x20, 0x0c, 0x10, 0xd9, 0x91, 0xd8, 0x08, 0x1a, 0x49, 0x71, 0x6b, 0xa3, 0x14, 0x55, 0xb5, 0x4e, 0x0f, 0xba, 0xa7, 0x2f, 0x75, 0xf3, 0xc1, 0xdb, 0x15, 0xf2, 0xea,
			0xb3, 0xac, 0xbb, 0x89, 0x74, 0xd1, 0x60, 0x8b, 0x26, 0x90, 0xbf, 0x86, 0x5c, 0xf7, 0x25, 0xd4, 0x96, 0x58, 0x70, 0x11, 0x1e, 0x02, 0xd0, 0x64, 0x36, 0xa1, 0x80, 0x46, 0xe3, 0xf6, 0xd7, 0x2b,
			0xa0, 0x28, 0x98, 0x8d, 0xf9, 0xc4, 0xfb, 0x4a, 0x48, 0xe9, 0x4d, 0xc8, 0x6e, 0xc3, 0x03, 0x6c, 0x1f, 0x76, 0x8f, 0x99, 0x8c, 0x54, 0xb6, 0xbd, 0x51, 0x31, 0x8a, 0x95, 0x97, 0xfe, 0x7c, 0x69,
			0x01, 0xbc, 0x92, 0xe8, 0x29, 0x67, 0x41, 0xf1, 0x0d, 0xa2, 0xd2, 0x85, 0xde, 0xfa, 0x05, 0x3a, 0x4b, 0x6d, 0x44, 0xfc, 0x5f, 0xc0, 0x81, 0xa5, 0x65, 0xcb, 0x5a, 0xf5, 0x40, 0x12, 0x7b, 0x94,
			0x7a, 0x1d, 0x13, 0xc9, 0xa8, 0x47, 0x04, 0x53, 0xa9, 0xfd, 0x3d, 0x24, 0xbe, 0x56, 0xef, 0xc7, 0x18, 0xb9, 0xf4, 0x42, 0x3b, 0x6a, 0xab, 0x2c, 0x9f, 0x3e, 0x5e, 0x07, 0xa4, 0xaf, 0xb2, 0x6f
		};

		static unsigned char decrypt_table[256] = {
			0x28, 0xc0, 0x95, 0xae, 0xe6, 0xce, 0x09, 0xfb, 0x6b, 0x0e, 0x25, 0x64, 0x66, 0xc8, 0x46, 0x75, 0x67, 0x93, 0xdd, 0xe2, 0x71, 0x7d, 0x0f, 0x2d, 0xf0, 0x55, 0x6c, 0x3c, 0x07, 0xe1, 0x94, 0xb0,
			0x65, 0x03, 0x11, 0x1a, 0xeb, 0x8e, 0x88, 0x38, 0xa1, 0xc4, 0x1e, 0x9f, 0xf7, 0x1c, 0x57, 0x78, 0x52, 0xb9, 0x22, 0x31, 0x33, 0x47, 0x98, 0x00, 0x5e, 0x4f, 0xcf, 0xf4, 0x30, 0xea, 0xf9, 0x41,
			0xdc, 0xc6, 0xf3, 0x3e, 0xd2, 0x21, 0x9b, 0xe5, 0xa8, 0x6d, 0xa7, 0xd0, 0x5d, 0xaa, 0x74, 0x19, 0x4a, 0xb8, 0x56, 0xe7, 0xb5, 0x72, 0xed, 0x27, 0x91, 0x0d, 0xda, 0x63, 0x8c, 0x20, 0xfa, 0xd4,
			0x86, 0x58, 0x60, 0x3d, 0x97, 0xd8, 0x51, 0xc5, 0x4b, 0xbf, 0xf5, 0x6f, 0xaf, 0xd1, 0xac, 0xff, 0x92, 0x6e, 0x50, 0x13, 0x84, 0x79, 0xb1, 0x32, 0x1f, 0x14, 0xe0, 0xde, 0xbe, 0x35, 0x23, 0x37,
			0x9a, 0xd6, 0x4e, 0x15, 0x26, 0xcb, 0x8b, 0x53, 0x2b, 0x83, 0xba, 0x87, 0xb4, 0xa3, 0x04, 0xb2, 0x89, 0x69, 0xc2, 0x62, 0xdf, 0xbb, 0x90, 0xbc, 0xa2, 0xb3, 0x2e, 0x24, 0x48, 0x18, 0x29, 0xf8,
			0xa0, 0x99, 0xc9, 0x70, 0xfc, 0xd7, 0x2f, 0x77, 0xe4, 0xe8, 0x1d, 0xf6, 0x81, 0x3f, 0x06, 0xfd, 0x12, 0x59, 0xfe, 0x80, 0x44, 0x73, 0xb6, 0x42, 0x49, 0xf1, 0x76, 0x82, 0xc1, 0xb7, 0xec, 0x8a,
			0xd5, 0x7b, 0x16, 0xad, 0xa5, 0x01, 0x0b, 0xef, 0xab, 0xe3, 0x36, 0xd9, 0x17, 0x5a, 0x3a, 0x08, 0x96, 0x85, 0xca, 0x39, 0x8f, 0x1b, 0x02, 0x9e, 0x6a, 0x68, 0x4c, 0x7c, 0x5f, 0x5c, 0xcc, 0x40,
			0x4d, 0x5b, 0x34, 0x9c, 0x10, 0x61, 0x54, 0x2c, 0xc3, 0xa9, 0x7f, 0x2a, 0x0c, 0x0a, 0x05, 0xee, 0x3b, 0xc7, 0x7e, 0x7a, 0xf2, 0xdb, 0x9d, 0x8d, 0x45, 0xa4, 0xcd, 0xa6, 0xd3, 0xe9, 0xbd, 0x43
		};

		encrypt_table_ = encrypt_table;
		decrypt_table_ = decrypt_table;
	}

	int encrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen)
	{
		dstLen = srcLen;
		while (srcLen-- > 0) {
			src[srcLen] = encrypt_table_[src[srcLen]];
		}

		*dst = src;
		return dstLen;
	}

	int decrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen)
	{
		dstLen = srcLen;
		while (srcLen-- > 0) {
			src[srcLen] = decrypt_table_[src[srcLen]];
		}

		*dst = src;
		return dstLen;
	}

	void release(boost::uint8_t* dst)
	{

	}

	void repeat(const std::string& request_host, boost::uint16_t request_port, std::string& proxy_host, boost::uint16_t& proxy_port)
	{
		proxy_host = proxy_host_;
		proxy_port = proxy_port_;

		boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
		lock_.lock();
		std::cout << "[" << boost::gregorian::to_iso_extended_string(now.date()) << " " << now.time_of_day() << "] proxy connect " << request_host << ":" << request_port << " to " << proxy_host << ":" << proxy_port << std::endl;
		lock_.unlock();
	}
};

#endif