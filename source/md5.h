//MD5.h 
#ifndef BZF_MD5_H
#define BZF_MD5_H

#include <string>
#include <iostream>


// a small class for calculating MD5 hashes of strings or byte arrays
// it is not meant to be fast or secure
//
// usage: 1) feed it blocks of uchars with update()
//      2) finalize()
//      3) get hexdigest() string
//      or
//      MD5(std::string).hexdigest()
//
// assumes that char is 8 bit and int is 32 bit
class MD5
{
	typedef unsigned char uint8; //  8bit
	typedef unsigned int uint32;  // 32bit

public:

	MD5();

	MD5(const std::string& text);
	
	void update(const char *input, uint32 length);

	void update(const unsigned char *input, uint32 length);

	MD5& finalize();

	const unsigned char* byte_digest();

	std::string hex_digest() const;

	friend std::ostream& operator<<(std::ostream&, MD5 md5);

private:
	void init();
	void transform(const uint8 block[64]);
	static void decode(uint32 output[], const uint8 input[], uint32 len);
	static void encode(uint8 output[], const uint32 input[], uint32 len);

	bool finalized;
	uint32 count[2];   // 64bit counter for number of bits (lo, hi)
	uint32 state[4];   // digest so far
	uint8 digest[16]; // the result
	uint8 buffer[64]; // bytes that didn't fit in last 64 byte chunk

	// low level logic operations
	static inline uint32 F(uint32 x, uint32 y, uint32 z);
	static inline uint32 G(uint32 x, uint32 y, uint32 z);
	static inline uint32 H(uint32 x, uint32 y, uint32 z);
	static inline uint32 I(uint32 x, uint32 y, uint32 z);
	static inline uint32 rotate_left(uint32 x, int n);
	static inline void FF(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac);
	static inline void GG(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac);
	static inline void HH(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac);
	static inline void II(uint32 &a, uint32 b, uint32 c, uint32 d, uint32 x, uint32 s, uint32 ac);
};

std::string md5(const std::string str);

#endif

