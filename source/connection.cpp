#include "acceptor.h"
#include "connection.h"
#include <boost/lexical_cast.hpp>
#include <boost/interprocess/detail/atomic.hpp>

connection::connection(const boost::shared_ptr<hive> hive)
: hive_(hive), socket_(hive->get_io_service()),io_strand_(hive->get_io_service())
, cache_buffer_size_(0), timer_interval_(15 * 1000), error_state_(0)
, timer_(hive->get_io_service()), recv_buffer_size_(4*1024)
{
	recv_buffer_ = new boost::uint8_t[recv_buffer_size_];
}

connection::~connection()
{
	delete []recv_buffer_;
	recv_buffer_ = 0;
}

boost::shared_ptr<hive> connection::get_hive() const
{
	return hive_;
}

boost::asio::ip::tcp::socket & connection::get_socket()
{
	return socket_;
}

void connection::set_timer_interval(boost::uint32_t timer_interval_ms)
{
	timer_interval_ = timer_interval_ms;
}

boost::uint32_t connection::get_timer_interval() const
{
	return timer_interval_;
}

void connection::bind(const std::string & ip, boost::uint16_t port)
{
	boost::asio::ip::tcp::endpoint endpoint(boost::asio::ip::address::from_string(ip), port);
	socket_.open(endpoint.protocol());
	socket_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
	socket_.bind(endpoint);
}

bool connection::connect(const std::string & host, boost::uint16_t port, boost::uint32_t timeout_milliseconds)
{
	try
	{	
		boost::asio::ip::tcp::resolver resolver(hive_->get_io_service());
		boost::asio::ip::tcp::resolver::query query(host, boost::lexical_cast<std::string>(port));
		boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
		
		boost::system::error_code ec;
		for (boost::asio::ip::tcp::resolver::iterator end; iterator != end; iterator++)
		{
			boost::unique_lock<boost::mutex> lock(mutex_);
			socket_.async_connect(*iterator, io_strand_.wrap(boost::bind(&connection::handle_connect, shared_from_this(), _1)));
			if (condition_.timed_wait(lock, boost::get_system_time() + boost::posix_time::milliseconds(timeout_milliseconds)))
			{
				if (socket_.is_open())
				{
					on_connect();
					start_recv();
					start_timer();
					return true;
				}
			}
			else
			{	
				socket_.close(ec);
				if (!condition_.timed_wait(lock, boost::get_system_time() + boost::posix_time::milliseconds(timeout_milliseconds)))
				{
					return false;
				}
			}
		}
		
		return false;
	}
	catch (...) {
		return false;
	}
}

boost::uint32_t connection::send(const boost::uint8_t* buffer, boost::uint32_t length)
{
	std::size_t sent = 0;
	boost::system::error_code ec;
	while (socket_.is_open() && sent != length && !ec) {
		sent += socket_.send(boost::asio::buffer(buffer + sent, length - sent), 0, ec);
	}

	last_time_ = boost::posix_time::microsec_clock::local_time();
	return (boost::uint32_t)sent;
}

void connection::disconnect()
{
	io_strand_.post(boost::bind(&connection::handle_timer, shared_from_this(), boost::asio::error::shut_down));
}

void connection::do_accept(const boost::shared_ptr<acceptor> acceptor)
{
	on_accept(acceptor);

	start_recv();
	start_timer();
}

void connection::do_error(const boost::system::error_code & error, bool inner)
{
	if (boost::interprocess::ipcdetail::atomic_cas32(&error_state_, 1, 0) == 0)
	{
		boost::system::error_code ec;
		socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
		socket_.close(ec);
		timer_.cancel(ec);
	}

	if (inner)
	{
		on_error(error);
	}
}

void connection::start_recv()
{
	last_time_ = boost::posix_time::microsec_clock::local_time();
	socket_.async_read_some(boost::asio::buffer(recv_buffer_ + cache_buffer_size_, recv_buffer_size_ - cache_buffer_size_), io_strand_.wrap(boost::bind(&connection::handle_recv, shared_from_this(), _1, _2)));
}

void connection::start_timer()
{	
	timer_.expires_from_now(boost::posix_time::milliseconds(timer_interval_));
	timer_.async_wait(io_strand_.wrap(boost::bind(&connection::dispatch_timer, shared_from_this(),_1)));
}

void connection::dispatch_timer(const boost::system::error_code & error)
{
	if (!error)
	{
		io_strand_.post(boost::bind(&connection::handle_timer, shared_from_this(), error));
	}
}

void connection::handle_recv(const boost::system::error_code & error, size_t transferred)
{
	if (error)
	{
		do_error(error, true);
	}
	else
	{
		boost::uint32_t used = std::min(on_recv(recv_buffer_, cache_buffer_size_ + (boost::uint32_t)transferred), cache_buffer_size_ + (boost::uint32_t)transferred);
		if (used > 0)
		{
			if (cache_buffer_size_ + (boost::uint32_t)transferred != used)
			{
				memmove(recv_buffer_, recv_buffer_ + used, cache_buffer_size_ + transferred - used);
			}	
		}

		cache_buffer_size_ = cache_buffer_size_ + (boost::uint32_t)transferred - used;

		if (5 * cache_buffer_size_ >= 4 * recv_buffer_size_) // 超过80%开始扩容
		{
			assign_copy();
		}

		start_recv();
	}
}

void connection::handle_connect(const boost::system::error_code & error)
{
	if (error)
	{
		boost::system::error_code ec;
		socket_.close(ec);
	}

	boost::unique_lock<boost::mutex> lock(mutex_);
	condition_.notify_one();
}

void connection::assign_copy() //呈2倍数扩容
{
	recv_buffer_size_ *= 2;
	boost::uint8_t *recv_buffer = new boost::uint8_t[recv_buffer_size_];
	memcpy(recv_buffer, recv_buffer_, cache_buffer_size_);

	delete []recv_buffer_;
	recv_buffer_ = recv_buffer;
}

void connection::handle_timer(const boost::system::error_code & error)
{
	if (error) 
	{
		do_error(error);
	}
	else 
	{
		if (timer_interval_ != 0) {
			boost::posix_time::time_duration duration = boost::posix_time::microsec_clock::local_time() - last_time_;
			if (timer_interval_ <= duration.total_milliseconds()) 
			{ 
				do_error(boost::asio::error::timed_out);// time out
			}
			else 
			{
				start_timer();
			}
		}
	}
}
