#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <boost/date_time.hpp>
#include <boost/thread/mutex.hpp>

void logging(const std::string & log)
{
	static boost::mutex lock_;
	boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
	lock_.lock();
	std::cout << "[" << boost::gregorian::to_iso_extended_string(now.date()) << " " << now.time_of_day() << "] " << log << std::endl;
	lock_.unlock();
}

#endif
