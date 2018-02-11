#ifndef _ACCEPTOR_H_
#define _ACCEPTOR_H_

#include "hive.h"
#include <boost/enable_shared_from_this.hpp>

class connection;
class acceptor : public boost::enable_shared_from_this< acceptor >
{
protected:
	explicit acceptor(const boost::shared_ptr< hive > hive);
	virtual ~acceptor();

public:
	// Begin listening on the specific network interface.
	void listen(const std::string & host, const boost::uint16_t & port);

	// Posts the connection to the listening interface. The next client that
	// connections will be given this connection. If multiple calls to Accept
	// are called at a time, then they are accepted in a FIFO order.
	void accept(const boost::shared_ptr< connection > connection);

	// Stop the Acceptor from listening.
	void stop();

	// Returns the Hive object.
	boost::shared_ptr< hive > get_hive() const;

	// Returns true if the Stop function has been called.
	bool has_stopped();

private:
	// Called when a connection has connected to the server. This function 
	// should return true to invoke the connection's OnAccept function if the 
	// connection will be kept. If the connection will not be kept, the 
	// connection's Disconnect function should be called and the function 
	// should return false.
	virtual bool on_accept(const boost::shared_ptr< connection > connection) = 0;

	// Called when an error is encountered. Most typically, this is when the
	// acceptor is being closed via the Stop function or if the Listen is 
	// called on an address that is not available.
	virtual void on_error(const boost::system::error_code & error) = 0;

private:

	void handle_error(const boost::system::error_code & error);

	void dispatch_accept(const boost::shared_ptr< connection > connection);

	void handle_accept(const boost::system::error_code & error, const boost::shared_ptr< connection > connection);

private:
	boost::asio::strand io_strand_;
	const boost::shared_ptr< hive > hive_;
	volatile boost::uint32_t error_state_;
	boost::asio::ip::tcp::acceptor acceptor_;
};


#endif
