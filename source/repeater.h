#ifndef _REPEATER_H_
#define _REPEATER_H_

#include <string>
#include <boost/cstdint.hpp>

class repeater
{
public:
	//ת������ص�
	virtual void repeat(const std::string& request_host, boost::uint16_t request_port, std::string& proxy_host, boost::uint16_t& proxy_port) = 0;

	//������err_unknown ���ݲ��㷵��err_no_more �ɹ�������ʹ��src�ĳ���
	virtual int encrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen) = 0;

	//������err_unknown ���ݲ��㷵��err_no_more �ɹ�������ʹ��src�ĳ���
	virtual int decrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen) = 0;

	//���ݻ�������
	virtual void release(bool is_encypt, boost::uint8_t* dst) = 0;
};

#endif
