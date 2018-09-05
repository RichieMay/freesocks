#include "acceptor.h"
#include "connection.h"
#include <boost/lexical_cast.hpp>
#include <boost/interprocess/detail/atomic.hpp>

acceptor::acceptor(const boost::shared_ptr< hive > hive)
: io_strand_(hive->get_io_service()), hive_(hive), error_state_(0), acceptor_(hive->get_io_service())
{
}

acceptor::~acceptor()
{
}

void acceptor::listen(const std::string & host, const boost::uint16_t & port)
{
	boost::asio::ip::tcp::resolver resolver(hive_->get_io_service());
	boost::asio::ip::tcp::resolver::query query(host, boost::lexical_cast<std::string>(port));
	boost::asio::ip::tcp::endpoint endpoint = *(resolver.resolve(query));

	acceptor_.open(endpoint.protocol());
	acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));

	acceptor_.bind(endpoint);
	acceptor_.listen(10);
}

void acceptor::accept(const boost::shared_ptr< connection > connection)
{
	io_strand_.post(boost::bind(&acceptor::dispatch_accept, shared_from_this(), connection));
}

void acceptor::stop()
{
	io_strand_.post(boost::bind(&acceptor::handle_error, shared_from_this(), boost::asio::error::shut_down));
}

bool acceptor::has_stopped()
{
	return (boost::interprocess::ipcdetail::atomic_cas32(&error_state_, 1, 1) == 1);
}

boost::shared_ptr<hive> acceptor::get_hive() const
{
	return hive_;
}

void acceptor::dispatch_accept(const boost::shared_ptr< connection > connection)
{
	acceptor_.async_accept(connection->get_socket(), boost::bind(&acceptor::handle_accept, shared_from_this(), _1, connection));
}

void acceptor::handle_accept(const boost::system::error_code & error, const boost::shared_ptr< connection > connection)
{
	if (error)
	{
		handle_error(error);
	}
	else
	{
		if (on_accept(connection)) 
		{
			connection->do_accept(shared_from_this());
		}
		else
		{
			connection->disconnect();
		}
	}
}

void acceptor::handle_error(const boost::system::error_code & error)
{
	if (boost::interprocess::ipcdetail::atomic_cas32(&error_state_, 1, 0) == 0)
	{
		boost::system::error_code ec;
		acceptor_.cancel(ec);
		acceptor_.close(ec);

		on_error(error);
	}
}
