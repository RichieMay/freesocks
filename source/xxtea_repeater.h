#ifndef _XXTEA_REPEATER_H_
#define _XXTEA_REPEATER_H_

#include "md5.h"
#include "types.h"
#include "repeater.h"
#include <boost/crc.hpp>
#include <boost/date_time.hpp>
#include <boost/thread/mutex.hpp>

/*
*	+--------------------------------------------------------------------------------------+
*	|  4 bytes  |  3 bytes  |  1 byte  |   2 bytes   |  2 bytes   | (dataLen+3)/4*4 bytes  |
*	+-----------+-----------+----------+---------------------------------------------------+
*	|  variable |   total   | fill len | total crc16 | data crc16 |    data + fill data    |
*	+--------------------------------------------------------------------------------------+
*/

class xxtea_repeater : public repeater
{
	#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

	typedef boost::uint32_t key_t[4];
public:
	xxtea_repeater(const std::string& proxy_host, boost::uint16_t proxy_port, const std::string& secret)
		: proxy_host_(proxy_host), proxy_port_(proxy_port)
	{
		string2key(secret);
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

	int encrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen)
	{
		dstLen = get_encrypt_length(srcLen);
		*dst = new boost::uint8_t[dstLen];
		boost::uint8_t* p = *dst;

		boost::uint32_t random = *((boost::uint32_t*)(&p));
		random = (random << 16) + (boost::posix_time::microsec_clock::universal_time().time_of_day().total_microseconds() & 0xffff);
		
		boost::uint32_t* variable = (boost::uint32_t*)p;
		*variable  = random; // variable
		p += sizeof(boost::uint32_t);

		boost::uint32_t* total_fill = (boost::uint32_t*)p;
		random = (boost::uint8_t)(dstLen - sizeof(boost::uint32_t) * 3 - srcLen);
		*total_fill = dstLen + (random << 24);//total and fill length
		p += sizeof(boost::uint32_t);

		boost::uint16_t* checksum = (boost::uint16_t*)p;
		*checksum = crc16_check((boost::uint8_t*)variable, sizeof(boost::uint32_t) * 2);//total crc16
		checksum++;
		p += sizeof(boost::uint32_t);

		memcpy(p, src, srcLen); // copy source
		*checksum = crc16_check(p, dstLen - sizeof(boost::uint32_t) * 3);//data crc16

		key_t key;
		obfuscation_key(*variable, key);

		btea(total_fill, 2, key);//cipher total and fill length

		boost::uint32_t cipherLen = dstLen - sizeof(boost::uint32_t) * 3;
		boost::int32_t n = cipherLen / sizeof(boost::uint32_t);
		btea((boost::uint32_t*)p, n, key);//cipher source

		return srcLen;
	}

	int decrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen)
	{
		key_t key;
		boost::uint16_t data_crc16 = 0;
		boost::uint32_t totalLen = 0, fillLen = 0;
		int ret = get_decrypt_length(src, srcLen, totalLen, fillLen, data_crc16, key);
		if (err_success != ret)
		{
			return ret;
		}

		boost::uint32_t cipherLen = totalLen - sizeof(boost::uint32_t) * 3;
		*dst = new boost::uint8_t[cipherLen]; //exclude srcLen、checksum
		boost::uint8_t* p = *dst;

		src += (sizeof(boost::uint32_t) * 3);
		memcpy(p, src, cipherLen); //copy cipher

		boost::int32_t n = cipherLen / sizeof(boost::uint32_t);//exclude srcLen、checksum
		btea((boost::uint32_t*)p, -n, key);
		
		if (data_crc16 != crc16_check(p, cipherLen))
		{
			return err_unknown;
		}

		dstLen = cipherLen - fillLen;
		return totalLen;
	}

	void release(boost::uint8_t* dst)
	{
		delete []dst;
	}

private:

	void string2key(const std::string& key)
	{
		MD5 md5(key);
		memcpy(key_, md5.byte_digest(), sizeof(key_t));
	}

	void btea(boost::uint32_t *v, boost::int32_t n, boost::uint32_t* key)
	{
		boost::uint32_t y, z, sum, DELTA = 0x9e3779b9;
		boost::int32_t p, r, e;
		if (n > 1) 
		{          /* Coding Part */
			r = 6 + 52 / n;
			sum = 0;
			z = v[n - 1];
			do 
			{
				sum += DELTA;
				e = (sum >> 2) & 3;
				for (p = 0; p < n - 1; p++)
				{
					y = v[p + 1];
					z = v[p] += MX;
				}
				y = v[0];
				z = v[n - 1] += MX;
			} while (--r);
		}
		else if (n < -1) 
		{  /* Decoding Part */
			n = -n;
			r = 6 + 52 / n;
			sum = r*DELTA;
			y = v[0];
			do 
			{
				e = (sum >> 2) & 3;
				for (p = n - 1; p > 0; p--)
				{
					z = v[p - 1];
					y = v[p] -= MX;
				}
				z = v[n - 1];
				y = v[0] -= MX;
				sum -= DELTA;
			} while (--r);
		}
	}

	boost::uint16_t crc16_check(boost::uint8_t* data, boost::uint32_t dataLen)
	{
		boost::crc_16_type crc16;
		crc16.process_bytes(data, dataLen);
		return crc16.checksum();
	}

	boost::uint32_t get_encrypt_length(boost::uint32_t srcLen)
	{
		return 12 + (srcLen + 3) / 4 * 4;
	}

	int get_decrypt_length(boost::uint8_t* data, boost::uint32_t dataLen, boost::uint32_t& totalLen, 
		boost::uint32_t& fillLen, boost::uint16_t& data_crc16, key_t& key)
	{
		if (dataLen <= (sizeof(boost::uint32_t) * 3))
		{
			return err_no_more;
		}
		
		boost::uint32_t* variable = (boost::uint32_t*)data; //variable
		data += sizeof(boost::uint32_t);

		obfuscation_key(*variable, key);

		boost::uint32_t* total_fill = (boost::uint32_t*)data; //total and fill length
		data += sizeof(boost::uint32_t);

		btea(total_fill, -2, key);//attention the code will modify source data

		data_crc16 = *((boost::uint16_t*)data);
		data += sizeof(boost::uint16_t);
		if (data_crc16 != crc16_check((boost::uint8_t*)variable, sizeof(boost::uint32_t) * 2))
		{
			return err_unknown;
		}
	
		totalLen = (*total_fill);
		fillLen = totalLen >> 24;
		totalLen = totalLen & 0xffffff;

		if (dataLen < totalLen)
		{
			return err_no_more;
		}

		data_crc16 = *((boost::uint16_t*)data);
		return err_success;
	}

	void obfuscation_key(const boost::uint32_t& timestamp, key_t& key)
	{
		boost::uint8_t* p = (boost::uint8_t*)(&timestamp);
		for (boost::uint8_t i = 0; i < 4; i++)
		{
			key[i] = key_[i] + p[i];
		}
	}

private:
	key_t key_;
	boost::mutex lock_;
	std::string proxy_host_;
	boost::uint16_t proxy_port_;
};

#endif
