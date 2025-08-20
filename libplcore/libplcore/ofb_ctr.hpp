/*
* CTR-BE Mode
* (C) 1999-2007 Jack Lloyd
*     2016-2019 Maxim Fukalov
* Distributed under the terms of the Botan license
*/
#pragma once
#ifndef BOTAN_OFB_CTR_BE_H__
#define BOTAN_OFB_CTR_BE_H__

#include <libplcore/botan_all.h>

namespace Botan {

/**
* OFB_CTR-BE (Counter mode, big-endian)
*/
class OFB_CTR_BE final : public StreamCipher
   {
   public:
      void cipher(const byte in[], byte out[], size_t length) override;

      void set_iv(const byte iv[], size_t iv_len) override;

      bool valid_iv_length(size_t iv_len) const override
         { return (iv_len <= permutation->block_size()); }

      Key_Length_Specification key_spec() const override
         {
         return permutation->key_spec();
         }

      std::string name() const override;

      OFB_CTR_BE* clone() const override
         { return new OFB_CTR_BE(permutation->clone()); }

      void clear() override;

      void seek(uint64_t offset) override {};

      /**
      * @param cipher the underlying block cipher to use
      */
      OFB_CTR_BE(BlockCipher* cipher);
      ~OFB_CTR_BE();
   private:
      void key_schedule(const byte key[], size_t key_len) override;
      void increment_counter();

      BlockCipher* permutation;
      SecureVector<byte> counter, buffer;
   };

}

#endif
