#ifndef _REPEATER_H_
#define _REPEATER_H_

#include <string>
#include <boost/cstdint.hpp>

class repeater
{
public:
	//转发请求回调
	virtual void repeat(const std::string& request_host, boost::uint16_t request_port, std::string& proxy_host, boost::uint16_t& proxy_port) = 0;

	//出错返回err_unknown 数据不足返回err_no_more 成功返回已使用src的长度
	virtual int encrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen) = 0;

	//出错返回err_unknown 数据不足返回err_no_more 成功返回已使用src的长度
	virtual int decrypt(boost::uint8_t* src, boost::uint32_t srcLen, boost::uint8_t** dst, boost::uint32_t& dstLen) = 0;

	//数据回收请求
	virtual void release(bool is_encypt, boost::uint8_t* dst) = 0;
};

#endif
