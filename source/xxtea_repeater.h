#ifndef _XXTEA_REPEATER_H_
#define _XXTEA_REPEATER_H_

#include "md5.h"
#include "types.h"
#include "repeater.h"
#include <boost/crc.hpp>
#include <boost/date_time.hpp>
#include <boost/thread/mutex.hpp>

/*
*	+-------------------------------------------------------------------------+
*	|  4 bytes  |  4 bytes  |  2 bytes  |  (dataLen+3)/4*4 bytes  |  4 bytes  |
*	+-----------+-----------+-----------+-------------------------------------+
*	|   total   | timestamp | checksum  |     data + fill data    |  dataLen  |
*	+-------------------------------------------------------------------------+
*/

class xxtea_repeater : public repeater
{
	#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

	typedef boost::uint32_t key_t[4];
public:
	xxtea_repeater(const std::string& proxy_host, boost::uint16_t proxy_port, const std::string& secret)
		: proxy_host_(proxy_host), proxy_port_(proxy_port), secret_(secret)
	{
		string2key(secret_);
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

		boost::uint32_t timestamp = boost::posix_time::microsec_clock::universal_time().time_of_day().total_microseconds() & 0xffffffff;
		
		boost::uint32_t blur_total = dstLen ^ dstLen + timestamp;
		memcpy(p, &blur_total, sizeof(boost::uint32_t));// blur total
		p += sizeof(boost::uint32_t);

		
		memcpy(p, &timestamp, sizeof(boost::uint32_t));// timestamp
		p += sizeof(boost::uint32_t);

		key_t key;
		obfuscation_key(timestamp, key);

		boost::uint16_t checksum = crc16_check(key, dstLen);
		memcpy(p, &checksum, sizeof(boost::uint16_t));// checksum
		p += sizeof(boost::uint16_t);

		memcpy(p, src, srcLen); // copy source

		boost::uint32_t cipherLen = dstLen - sizeof(boost::uint32_t) * 2 - sizeof(boost::uint16_t);
		memcpy(p + cipherLen - sizeof(boost::uint32_t), &srcLen, sizeof(boost::uint32_t)); //source length 

		boost::int32_t n = cipherLen / sizeof(boost::uint32_t);
		btea((boost::uint32_t*)p, n, key);

		return srcLen;
	}

	int decrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen)
	{
		key_t key;
		boost::uint32_t totalLen = 0;
		int ret = get_decrypt_length(src, srcLen, totalLen, key);
		if (ret != err_success)
		{
			return ret;
		}

		if (srcLen < totalLen)
		{
			return err_no_more;
		}

		boost::uint32_t cipherLen = totalLen - sizeof(boost::uint32_t) * 2 - sizeof(boost::uint16_t);
		*dst = new boost::uint8_t[cipherLen]; //exclude srcLen、checksum
		boost::uint8_t* p = *dst;

		src += ((sizeof(boost::uint32_t) * 2 + sizeof(boost::uint16_t)));
		memcpy(p, src, cipherLen); //copy cipher

		boost::int32_t n = cipherLen / sizeof(boost::uint32_t);//exclude srcLen、checksum
		btea((boost::uint32_t*)p, -n, key);
		
		p += (cipherLen - sizeof(boost::uint32_t));
		dstLen = *((boost::uint32_t*)p);
		return (totalLen == get_encrypt_length(dstLen) ? totalLen : err_unknown);
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

	boost::uint16_t crc16_check(const key_t &key, boost::uint32_t totalLen)
	{
		boost::crc_16_type crc16;
		crc16.process_bytes((boost::uint8_t*)key, sizeof(key_t));
		crc16.process_bytes((boost::uint8_t*)(&totalLen), sizeof(boost::uint32_t));
		return crc16.checksum();
	}

	boost::uint32_t get_encrypt_length(boost::uint32_t srcLen)
	{
		return 14 + (srcLen + 3) / 4 * 4;
	}

	int get_decrypt_length(boost::uint8_t* data, boost::uint32_t dataLen, boost::uint32_t& totalLen, key_t& key)
	{
		if (dataLen < (sizeof(boost::uint32_t) * 2 + sizeof(boost::uint16_t)))
		{
			return err_no_more;
		}
		
		boost::uint32_t blur_total = *((boost::uint32_t*)data); //blur total
		data += sizeof(boost::uint32_t);

		boost::uint32_t timestamp = *((boost::uint32_t*)data); //timestamp
		data += sizeof(boost::uint32_t);

		blur_total -= timestamp;
		totalLen = blur_total ^ blur_total;

		obfuscation_key(timestamp, key);
		boost::uint16_t checksum = *((boost::uint16_t*)data); //checksum
		if (checksum != crc16_check(key, totalLen))
		{
			return err_unknown;
		}
		else
		{
			return err_success;
		}
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
	std::string secret_;
	std::string proxy_host_;
	boost::uint16_t proxy_port_;
};

#endif
