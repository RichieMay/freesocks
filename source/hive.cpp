#include "hive.h"
#include <boost/interprocess/detail/atomic.hpp>

hive::hive()
 : work_(io_service_), shutdown_(0)
{

}

hive::~hive()
{

}

boost::asio::io_service & hive::get_io_service()
{
	return io_service_;
}

bool hive::has_stopped()
{
	return (boost::interprocess::ipcdetail::atomic_cas32(&shutdown_, 1, 1) == 1);
}

void hive::poll()
{
	io_service_.poll();
}

void hive::run()
{
	io_service_.run();
}

void hive::stop()
{
	if (boost::interprocess::ipcdetail::atomic_cas32(&shutdown_, 1, 0) == 0)
	{
		io_service_.stop();
	}
}