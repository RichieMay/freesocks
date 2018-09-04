#include "hive.h"
#include "acceptor.h"
#include "connection.h"
#include "xxtea_repeater.h"
#include <boost/program_options.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp> 
#include <boost/date_time/posix_time/posix_time.hpp>

#define CHECK_DATA_LENGTH(dl,nl) \
if (dl < nl) {\
	return err_no_more;\
}

class client : public connection
{
	enum status { select_method, proxy_wait, proxy_request, proxy_request_reply, proxy_body_repeat };
public:
	enum mode { socks, redsocks, freesocks };

	client(boost::shared_ptr< hive > hive, boost::shared_ptr< repeater > repeater, mode type)
		: connection(hive), local_ip_("0.0.0.0"), local_port_(0), repeater_(repeater), mode_(type)
		, status_(type != socks ? proxy_request : select_method)
	{

	}

	boost::shared_ptr< repeater > get_repeater() const
	{
		return repeater_;
	}

	mode get_mode() const
	{
		return mode_;
	}

private:
	mode mode_;
	status status_;
	std::string local_ip_;
	boost::uint16_t local_port_;
	boost::shared_ptr< client > client_;
	boost::shared_ptr< repeater > repeater_;

private:

	void on_accept(const boost::shared_ptr< acceptor > acceptor)
	{
#ifdef __linux__
#ifndef SO_ORIGINAL_DST
	#define SO_ORIGINAL_DST 80
#endif
		if (mode_ == redsocks)
		{
			struct sockaddr_storage addr_storage;
			socklen_t addr_len = sizeof(addr_storage);
			int ret = getsockopt(get_socket().native_handle(), SOL_IP, SO_ORIGINAL_DST, &addr_storage, &addr_len);
			//ret = getpeername(fd, (struct sockaddr *) &addr_storage, &addr_len);
			if (0 != ret)
			{
				disconnect();
				return;
			}

			struct sockaddr* addr = (struct sockaddr *) &addr_storage;
			boost::uint8_t request[22] = { 0x05, 0x01, 0x00, ss5_ipv4 };
			boost::uint32_t request_len = sizeof(request);
			if (addr->sa_family == AF_INET)
			{
				request[3] = ss5_ipv4;
				struct sockaddr_in* addr_v4 = (struct sockaddr_in*)addr;
				boost::uint32_t* addr_v4_ip = (boost::uint32_t*)(request + sizeof(ss5_proxy_request));
				*addr_v4_ip = (boost::uint32_t)addr_v4->sin_addr.s_addr;

				boost::uint16_t* addr_v4_port = (boost::uint16_t*)(request + sizeof(ss5_proxy_request) + sizeof(boost::uint32_t));
				*addr_v4_port = addr_v4->sin_port;

				request_len = sizeof(ss5_proxy_request) + sizeof(boost::uint32_t) + sizeof(boost::uint16_t);
			}
			else if (addr->sa_family == AF_INET6)
			{
				request[3] = ss5_ipv6;
				struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)addr;
				memcpy(request + sizeof(ss5_proxy_request), addr_v6->sin6_addr.s6_addr, sizeof(addr_v6->sin6_addr.s6_addr));

				boost::uint16_t* addr_v6_port = (boost::uint16_t*)(request + sizeof(ss5_proxy_request) + sizeof(addr_v6->sin6_addr.s6_addr));
				*addr_v6_port = addr_v6->sin6_port;

				request_len = sizeof(ss5_proxy_request) + sizeof(addr_v6->sin6_addr.s6_addr) + sizeof(boost::uint16_t);
			}
			else
			{
				disconnect();
				return;
			}

			handle_parse_proxy_request(request, request_len);
		}
#endif
	}

	void on_connect()
	{
		boost::system::error_code ec;
		boost::asio::ip::tcp::endpoint ep = get_socket().local_endpoint(ec);
		if (!ec)
		{
			local_port_ = ep.port();
			local_ip_ = ep.address().to_string();
		}
	}

	boost::uint32_t on_recv(boost::uint8_t* buffer, boost::uint32_t length)
	{
		bool no_error = true;
		boost::uint32_t recv_used = 0;

		do
		{
			boost::uint8_t* dst = buffer + recv_used;
			boost::uint32_t dstLen = length - recv_used;

			boost::int32_t decrypt_used = length - recv_used;
			if (mode_ == freesocks) //freesocks client / server的数据需要解码
			{
				decrypt_used = repeater_->decrypt(buffer + recv_used, length - recv_used, &dst, dstLen);
			}

			if (decrypt_used == err_no_more) //数据不足
			{
				no_error = false;
			}
			else if (decrypt_used < err_success) //解码出错
			{
				no_error = false;
				disconnect();
			}
			else //解码成功并且返回已使用的数据长度
			{
				int ret = handle_parse_packet(dst, dstLen);
				if (err_success != ret)
				{
					no_error = false;
					if (err_no_more != ret)
					{
						disconnect();
					}
				}
				else
				{
					recv_used += decrypt_used;
				}

				if (mode_ == freesocks)
				{
					repeater_->release(dst);
				}
			}
		} while (no_error && (recv_used < length));

		return recv_used;
	}

	void on_error(const boost::system::error_code & error)
	{
		if (client_)
		{
			client_->disconnect();
			client_.reset();
		}
	}

private:

	boost::uint32_t handle_send(boost::uint8_t* buffer, boost::uint32_t length)
	{
		boost::uint8_t* dst = buffer;
		boost::uint32_t dstLen = length;
		boost::int32_t ret = 0;

		if (mode_ == freesocks) //freesocks client / server的数据需要编码
		{
			ret = repeater_->encrypt(buffer, length, &dst, dstLen);
		}

		if (ret < err_success) {
			return 0;
		}

		ret = send(dst, dstLen);
		if (mode_ == freesocks)
		{
			repeater_->release(dst);
		}

		if (ret != dstLen)
		{
			return 0;
		}

		return length;
	}

	boost::int32_t handle_parse_packet(boost::uint8_t* data, boost::uint32_t dataLen)
	{
		switch (status_)
		{
		case select_method:
			return handle_parse_select_method(data, dataLen);
		case proxy_request:
			return handle_parse_proxy_request(data, dataLen);
		case proxy_body_repeat:
			return handle_parse_proxy_content(data, dataLen);
		case proxy_request_reply:
			return handle_parse_proxy_request_reply(data, dataLen);
		case proxy_wait:
			return handle_parse_proxy_wait(data, dataLen);
		default:
			return err_unsupported;
		}
	}

	boost::int32_t handle_parse_select_method(boost::uint8_t* data, boost::uint32_t dataLen)
	{
		CHECK_DATA_LENGTH(dataLen, sizeof(ss5_select_request));
		ss5_select_request* request = (ss5_select_request*)data;
		if (request->ver != 0x05) //SOCKS5 version=0x05
		{
			return err_protocol;
		}

		CHECK_DATA_LENGTH(dataLen, sizeof(ss5_select_request) + request->nmethods);

		for (unsigned int i = 0; i < request->nmethods; i++)
		{
			if (request->methods[i] == 0x00) //SOCKS5 no auth
			{
				ss5_select_response response;
				response.ver = request->ver;
				response.method = request->methods[i];
				if (sizeof(response) != handle_send((boost::uint8_t*)&response, sizeof(response)))
				{
					return err_unknown;
				}

				status_ = proxy_request;
				return err_success;
			}
		}

		return err_unsupported;
	}

	boost::int32_t handle_parse_proxy_request(boost::uint8_t* data, boost::uint32_t dataLen)
	{
		boost::uint32_t pos = 0;
		CHECK_DATA_LENGTH(dataLen, sizeof(ss5_proxy_request));
		ss5_proxy_request* request = (ss5_proxy_request*)(data + pos);
		if (request->ver != 0x05 || request->rsv != 0x00)
		{
			return err_protocol;
		}

		pos += sizeof(ss5_proxy_request);

		ss5_porxy_address address;
		switch (request->atyp)
		{
			case ss5_ipv4:
				{
					unsigned int ipv4 = 0;
					CHECK_DATA_LENGTH(dataLen, pos + sizeof(ipv4) + sizeof(address.port));	//IPV4: INT + SHORT

					memcpy(&ipv4, data + pos, sizeof(ipv4));
					pos += sizeof(ipv4);

					memcpy(&address.port, data + pos, sizeof(address.port));
					pos += sizeof(address.port);

					address.host = boost::asio::ip::address_v4(boost::asio::detail::socket_ops::network_to_host_long(ipv4)).to_string();
				}
				break;
			case ss5_fqdn:
				{
					CHECK_DATA_LENGTH(dataLen, pos + sizeof(unsigned char));	//DOMAIN: CHAR
					unsigned char domain_len = *(data + pos);
					pos += sizeof(unsigned char);

					CHECK_DATA_LENGTH(dataLen, pos + domain_len + sizeof(address.port)); //DOMAIN: STRING + SHORT
					address.host = std::string((char*)data + pos, domain_len);
					pos += domain_len;

					memcpy(&address.port, data + pos, sizeof(address.port));
					pos += sizeof(address.port);
				}
				break;
			case ss5_ipv6:
				{
					boost::asio::detail::array<unsigned char, 16> ipv6;
					CHECK_DATA_LENGTH(dataLen, pos + sizeof(unsigned int) * 4 + sizeof(unsigned short));	//IPV6: 16 + SHORT
					memcpy(ipv6.data(), data + pos, ipv6.size());
					pos += ((uint32_t)ipv6.size());

					memcpy(&address.port, data + pos, sizeof(address.port));
					pos += sizeof(address.port);

					address.host = boost::asio::ip::address_v6(ipv6).to_string();
				}
				break;
			default:
				return err_protocol;
		}

		address.port = boost::asio::detail::socket_ops::network_to_host_short(address.port);

		switch (request->cmd)
		{
			case ss5_connect:
				handle_parse_cmd_connect(data, pos, &address);
				break;
			case ss5_bind:
			case ss5_udp_associate:
				return err_unsupported;
			default:
				return err_protocol;
		}

		return err_success;
	}

	boost::int32_t handle_parse_proxy_request_reply(boost::uint8_t* data, boost::uint32_t dataLen)
	{
		CHECK_DATA_LENGTH(dataLen, sizeof(ss5_proxy_response));
		ss5_proxy_response* response = (ss5_proxy_response*)data;
		if (response->ver != 0x05 || response->rep != 0x00)
		{
			return err_protocol;
		}

		//回复BIND IP PORT
		boost::uint8_t buf[22] = { 0 }, bufLen = 0;//头 + IPV4/IPV6 + PORT
		response = (ss5_proxy_response*)buf;
		response->ver = 0x05;
		response->rsv = 0x00;

		boost::asio::ip::address addr = boost::asio::ip::address::from_string(local_ip_);
		boost::uint16_t port = boost::asio::detail::socket_ops::host_to_network_short(local_port_);
		if (addr.is_v4())
		{
			bufLen = 10;
			response->atyp = ss5_ipv4;
			boost::uint32_t ipv4 = (boost::uint32_t)boost::asio::detail::socket_ops::host_to_network_long(addr.to_v4().to_ulong());
			memcpy(buf + sizeof(ss5_proxy_response), &ipv4, sizeof(boost::uint32_t));
			memcpy(buf + sizeof(ss5_proxy_response) + sizeof(boost::uint32_t), &port, sizeof(boost::uint16_t));
		}
		else
		{
			bufLen = 22;
			response->atyp = ss5_ipv6;
			memcpy(buf + sizeof(ss5_proxy_response), local_ip_.c_str(), 16);
			memcpy(buf + sizeof(ss5_proxy_response) + 16, &port, sizeof(boost::uint16_t));
		}

		if (client_->mode_ != redsocks)
		{
			if (bufLen != client_->handle_send(buf, bufLen))
			{
				return err_unknown;
			}
		}

		client_->status_ = status_ = proxy_body_repeat;
		return err_success;
	}

	boost::int32_t handle_parse_proxy_content(boost::uint8_t* data, boost::uint32_t dataLen)
	{
		if (client_)
		{
			if (dataLen != client_->handle_send(data, dataLen))
			{
				return err_unknown;
			}
		}

		return err_success;
	}

	boost::int32_t handle_parse_proxy_wait(boost::uint8_t* data, boost::uint32_t dataLen)
	{
		if (mode_ == redsocks)//透明代理模式继续发送数据即可
		{
			return handle_parse_proxy_content(data, dataLen);
		}
		else
		{
			return err_protocol;
		}
	}

	void handle_parse_cmd_connect(boost::uint8_t* data, boost::uint32_t dataLen, const ss5_porxy_address* address)
	{
		ss5_porxy_address proxy_address = *address;
		if (mode_ == freesocks) //freesocks client
		{
			client_.reset(new client(get_hive(), repeater_, socks));//freesocks client, freesocks server
		}
		else //socks
		{
			repeater_->repeat(address->host, address->port, proxy_address.host, proxy_address.port);
			if (address->host != proxy_address.host || address->port != proxy_address.port)
			{
				client_.reset(new client(get_hive(), repeater_, freesocks));//freesocks client, freesocks server
			}
			else if(mode_ == socks)
			{
				client_.reset(new client(get_hive(), repeater_, socks));//freesocks client, freesocks server
			}
			else
			{
				return disconnect();
			}
		}

		boost::uint8_t buf[22] = { 0 }, bufLen = 10;//头 + IPV4/IPV6 + PORT
		ss5_proxy_response* response = (ss5_proxy_response*)buf;
		response->ver = 0x05;
		response->rsv = 0x00;
		response->atyp = ss5_ipv4;

		if (client_->connect(proxy_address.host, proxy_address.port))
		{
			if (client_->mode_ == freesocks)
			{
				status_ = proxy_wait;//等待 freesocks server 响应
				client_->status_ = proxy_request_reply;
				client_->client_ = boost::dynamic_pointer_cast<client>(shared_from_this());
				if (dataLen != client_->handle_send(data, dataLen)) //向 freesocks server 发送代理请求
				{
					disconnect();
				}
			}
			else if(client_->mode_ == socks)
			{
				response->rep = 0x00;//succeeded

				boost::asio::ip::address addr = boost::asio::ip::address::from_string(client_->local_ip_);
				boost::uint16_t port = boost::asio::detail::socket_ops::host_to_network_short(client_->local_port_);
				if (addr.is_v4())
				{
					bufLen = 10;
					response->atyp = ss5_ipv4;
					boost::uint32_t ipv4 = (boost::uint32_t)boost::asio::detail::socket_ops::host_to_network_long(addr.to_v4().to_ulong());
					memcpy(buf + sizeof(ss5_proxy_response), &ipv4, sizeof(boost::uint32_t));
					memcpy(buf + sizeof(ss5_proxy_response) + sizeof(boost::uint32_t), &port, sizeof(boost::uint16_t));
				}
				else
				{
					bufLen = 22;
					response->atyp = ss5_ipv6;
					memcpy(buf + sizeof(ss5_proxy_response), client_->local_ip_.c_str(), 16);
					memcpy(buf + sizeof(ss5_proxy_response) + 16, &port, sizeof(boost::uint16_t));
				}

				if (bufLen == handle_send(buf, bufLen))
				{
					client_->status_ = status_ = proxy_body_repeat;
					client_->client_ = boost::dynamic_pointer_cast<client>(shared_from_this());
				}
				else
				{
					disconnect();
				}
			}
			else //unreachable block
			{
				disconnect();
			}
		}
		else
		{
			response->rep = 0x07;
			handle_send(buf, bufLen);
			disconnect();
		}
	}
};

class server : public acceptor
{
private:
	bool on_accept(const boost::shared_ptr< connection > connection)
	{
		boost::shared_ptr< client > cli = boost::dynamic_pointer_cast<client>(connection);
		accept(boost::shared_ptr< client >(new client(cli->get_hive(), cli->get_repeater(), cli->get_mode())));
		return true;
	}

	void on_error(const boost::system::error_code & error)
	{
		std::cout << error << std::endl;
	}

public:
	server(boost::shared_ptr< hive > hive)
		: acceptor(hive)
	{
	}
};

class service : public boost::enable_shared_from_this< service >
{
public:
	service(boost::shared_ptr< hive > hive)
		: hive_(hive), listen_ip_("127.0.0.1"), listen_port_(1080), redirect_(false)
	{

	}

	bool parse(int argc, const char** argv)
	{
		boost::program_options::options_description opts("freesocks options");
		opts.add_options()
			("help,h", "help info") //多个参数
#ifdef __linux__
			("redir,r", "redirect mode")
#endif
			("bind,b", boost::program_options::value<std::string>(), "bind ip:port,default:127.0.0.1:1080")
			("conf,c", boost::program_options::value<std::string>(), "config file")
			("key,k", boost::program_options::value<std::string>(), "secret key")
			("server,s", boost::program_options::value<std::string>(), "server host:port");

		try
		{
			boost::program_options::variables_map vm;
			boost::program_options::store(boost::program_options::parse_command_line(argc, argv, opts), vm);
			boost::program_options::notify(vm);
			if (vm.count("help") || vm.empty())
			{
				std::cout << opts << std::endl;
				return false;
			}

			if (vm.count("conf"))
			{
				parse_config(vm["conf"].as<std::string>());
				return true;
			}

			if (vm.count("bind"))
			{
				std::string bind_ip_port = vm["bind"].as<std::string>();
				size_t pos = bind_ip_port.find(":");
				if (pos != std::string::npos)
				{
					listen_ip_ = bind_ip_port.substr(0, pos);
					listen_port_ = boost::lexical_cast<boost::uint16_t>(bind_ip_port.substr(pos + 1));
				}
				else
				{
					std::cout << opts << std::endl;
					return false;
				}
			}

			if (vm.count("key"))
			{
				key_ = vm["key"].as<std::string>();
			}

#ifdef __linux__
			if (vm.count("redir"))
			{	
				if (!vm.count("server"))
				{
					std::cout << "redirect mode should config server" << std::endl;
					return false;
				}

				redirect_ = true;
			}
#endif
			if (vm.count("server"))
			{
				std::string server_ip_port = vm["server"].as<std::string>();
				size_t pos = server_ip_port.find(":");
				if (pos != std::string::npos)
				{
					server_ip_ = server_ip_port.substr(0, pos);
					server_port_ = boost::lexical_cast<boost::uint16_t>(server_ip_port.substr(pos + 1));
				}
				else
				{
					std::cout << opts << std::endl;
					return false;
				}
			}

			return true;
		}
		catch (...) {
			std::cout << opts << std::endl;
			return false;
		}

	}

	int run()
	{
		boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
		std::cout << "[" << boost::gregorian::to_iso_extended_string(now.date()) << " " << now.time_of_day()
			<< (is_server_mode() ? "] freesocks server started " :
			(is_redirect_mode() ? "] freesocks redirect started " :"] freesocks client started "))
			<< listen_ip_ << ":" << listen_port_ << std::endl;

		boost::thread_group thread_group_;
		size_t cpu_num = boost::thread::hardware_concurrency();
		size_t _threads_num = cpu_num * 2 + 1;
		for (size_t i = 0; i < _threads_num; i++)
		{
			thread_group_.create_thread(boost::bind(&hive::run, hive_));
		}

		boost::asio::signal_set signals(hive_->get_io_service(), SIGINT, SIGTERM);
		signals.async_wait(boost::bind(&service::handler_signal, shared_from_this(), _1, _2));

		thread_group_.join_all();
		return 0;
	}

	bool is_server_mode() const
	{
		return server_ip_.empty();
	}

	bool is_redirect_mode() const {
		return redirect_;
	}

	std::string get_key() const
	{
		return key_;
	}

	std::string get_listen_ip() const
	{
		return listen_ip_;
	}

	boost::uint16_t get_listen_port() const
	{
		return listen_port_;
	}

	std::string get_server_ip() const
	{
		return server_ip_;
	}

	boost::uint16_t get_server_port() const
	{
		return server_port_;
	}

private:
	void parse_config(const std::string& conf)
	{
		boost::property_tree::ptree reader;
		boost::property_tree::json_parser::read_json(conf, reader);
		key_ = reader.get<std::string>("key", key_);
#ifdef __linux__
		redirect_ = reader.get<bool>("redirect", redirect_);
#endif
		listen_ip_ = reader.get<std::string>("listen_ip", listen_ip_);
		listen_port_ = reader.get<boost::uint16_t>("listen_port", listen_port_);
		server_ip_ = reader.get<std::string>("server_ip", server_ip_);
		server_port_ = reader.get<boost::uint16_t>("server_port", server_port_);
	}

	void handler_signal(boost::system::error_code error, int signal_number)
	{
		hive_->stop();

		boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
		std::cout << "[" << boost::gregorian::to_iso_extended_string(now.date()) << " " << now.time_of_day()
			<< (is_server_mode() ? "] freesocks server stopped" :
			(is_redirect_mode() ? "] freesocks redirect stopped " : "] freesocks client stopped ")) << std::endl;
	}

private:
	bool redirect_;
	std::string key_;
	std::string listen_ip_;
	std::string server_ip_;
	boost::uint16_t listen_port_;
	boost::uint16_t server_port_;
	boost::shared_ptr< hive > hive_;
};

int main(int argc, const char * argv[])
{
	boost::shared_ptr< hive > _hive(new hive());
	boost::shared_ptr< service > _service(new service(_hive));
	if (!_service->parse(argc, argv))
	{
		return 0;
	}

	boost::shared_ptr< xxtea_repeater > _repeater(new xxtea_repeater(_service->get_server_ip(), _service->get_server_port(), _service->get_key()));

	boost::shared_ptr< server > _server(new server(_hive));
	_server->listen(_service->get_listen_ip(), _service->get_listen_port());
	_server->accept(boost::shared_ptr< client >(new client(_hive, _repeater, _service->is_server_mode() ? client::freesocks : 
		(_service->is_redirect_mode() ? client::redsocks : client::socks))));

	return _service->run();
}
