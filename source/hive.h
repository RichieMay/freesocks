#ifndef _HIVE_H_
#define _HIVE_H_

#include <boost/asio.hpp>
#include <boost/thread.hpp>

class hive
{
public:
	hive();
	virtual ~hive();

	// Returns the io_service of this object.
	boost::asio::io_service & get_io_service();

	// Returns true if the Stop function has been called.
	bool has_stopped();

	// Polls the networking subsystem once from the current thread and 
	// returns.
	void poll();

	// Runs the networking system on the current thread. This function blocks 
	// until the networking system is stopped, so do not call on a single 
	// threaded application with no other means of being able to call Stop 
	// unless you code in such logic.
	void run();

	// Stops the networking system. All work is finished and no more 
	// networking interactions will be possible afterwards until Reset is called.
	void stop();

private:
	volatile boost::uint32_t shutdown_;
	boost::asio::io_service io_service_;
	boost::asio::io_service::work work_;
};

#endif
