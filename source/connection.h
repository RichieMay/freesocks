#ifndef _CONNECTION_H_
#define _CONNECTION_H_

#include "hive.h"
#include <boost/enable_shared_from_this.hpp>

class acceptor;
class connection : public boost::enable_shared_from_this<connection>
{
	friend class acceptor;
protected:
	explicit connection(const boost::shared_ptr< hive > hive);
	virtual ~connection();

public:

	// Returns the Hive object.
	boost::shared_ptr< hive > get_hive() const;

	// Returns the socket object.
	boost::asio::ip::tcp::socket & get_socket();

	// Sets the timer interval of the object. The interval is changed after 
	// the next update is called.
	void set_timer_interval(boost::uint32_t timer_interval_ms);

	// Returns the timer interval of the object.
	boost::uint32_t get_timer_interval() const;

	// Binds the socket to the specified interface.
	void bind(const std::string & ip, boost::uint16_t port);

	// Starts an synchronous connect.
	bool connect(const std::string & host, boost::uint16_t port, boost::uint32_t timeout_milliseconds = 5000);

	//data to be sent to the connection.
	boost::uint32_t send(const boost::uint8_t* buffer, boost::uint32_t length);

	// Posts an asynchronous disconnect event for the object to process.
	void disconnect();

private:
	// Called when the connection has successfully connected to the local
	// host.
	virtual void on_accept(const boost::shared_ptr< acceptor > acceptor) = 0;

	// Called when the connection has successfully connected to the remote
	// host.
	virtual void on_connect() = 0;

	// Called when data has been received by the connection. 
	virtual boost::uint32_t on_recv(boost::uint8_t* buffer, boost::uint32_t length) = 0;

	// Called when an error is encountered.
	virtual void on_error(const boost::system::error_code & error) = 0;

private:
	void assign_copy();

	void start_recv();

	void start_timer();

	void do_accept(const boost::shared_ptr<acceptor> acceptor);

	void handle_timer(const boost::system::error_code & error);

	void dispatch_timer(const boost::system::error_code & error);

	void do_error(const boost::system::error_code & error, bool inner = false);

	void handle_recv(const boost::system::error_code & error, size_t transferred);

	void handle_connect(const boost::system::error_code & error);

private:
	boost::mutex mutex_;
	boost::uint8_t *recv_buffer_;
	boost::asio::strand io_strand_;
	boost::uint32_t timer_interval_;
	boost::uint32_t recv_buffer_size_;
	boost::uint32_t cache_buffer_size_;
	boost::asio::deadline_timer timer_;
	boost::posix_time::ptime last_time_;
	boost::asio::ip::tcp::socket socket_;
	boost::condition_variable condition_;
	volatile boost::uint32_t error_state_;
	const boost::shared_ptr< hive > hive_;
};

#endif



