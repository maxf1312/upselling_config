/*
* Counter mode
* (C) 1999-2011 Jack Lloyd
*     2016-2019 Maxim Fukalov
* Distributed under the terms of the Botan license
*/
#include <libplcore/ofb_ctr.hpp>

namespace Botan {
	
/*
* OFB_CTR-BE Constructor
*/

OFB_CTR_BE::OFB_CTR_BE(BlockCipher* ciph) :
   permutation(ciph),
   counter(permutation->block_size()),
   buffer(counter.size())
   {
   }

/*
* OFB_CTR_BE Destructor
*/
   OFB_CTR_BE::~OFB_CTR_BE()
   {
   delete permutation;
   }

/*
* Zeroize
*/
   void OFB_CTR_BE::clear()
   {
   permutation->clear();
   zeroise(buffer);
   zeroise(counter);
   }

/*
* Set the key
*/
void OFB_CTR_BE::key_schedule(const byte key[], size_t key_len)
   {
   permutation->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(0, 0);
   }

/*
* Return the name of this type
*/
std::string OFB_CTR_BE::name() const
   {
   return ("OFB_CTR-BE(" + permutation->name() + ")");
   }

/*
* OFB_CTR-BE Encryption/Decryption
*/
void Botan::OFB_CTR_BE::cipher(const byte in[], byte out[], size_t length)
	{
		// On each byte we need to increment counter
		for(; length-- > 0; increment_counter())
			*out++ = *in++ ^ buffer[0];
	}

/*
* Set OFB_CTR-BE IV
*/
void OFB_CTR_BE::set_iv(const byte iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   zeroise(counter);
   //counter.copy(0, iv, iv_len);
   std::copy(iv, iv + iv_len, counter.begin());
   permutation->encrypt(&counter[0], &buffer[0]);
   }

/*
* Increment the counter and update the buffer
*/
void OFB_CTR_BE::increment_counter()
	{
	const size_t bs = permutation->block_size();

	for(size_t j = 1; j != bs; ++j)
		   if(++counter[bs - j])
            break;

	permutation->encrypt(&counter[0], &buffer[0]);
   }

}

