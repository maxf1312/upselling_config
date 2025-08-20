/*
* Botan 2.12.1 Amalgamation
* (C) 1999-2018 The Botan Authors
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "botan_all.h"
#include "botan_all_internal.h"

/*
* (C) 2019 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

void Buffered_Computation::update_be(uint16_t val)
   {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data(inb, sizeof(inb));
   }

void Buffered_Computation::update_be(uint32_t val)
   {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data(inb, sizeof(inb));
   }

void Buffered_Computation::update_be(uint64_t val)
   {
   uint8_t inb[sizeof(val)];
   store_be(val, inb);
   add_data(inb, sizeof(inb));
   }

void Buffered_Computation::update_le(uint16_t val)
   {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data(inb, sizeof(inb));
   }

void Buffered_Computation::update_le(uint32_t val)
   {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data(inb, sizeof(inb));
   }

void Buffered_Computation::update_le(uint64_t val)
   {
   uint8_t inb[sizeof(val)];
   store_le(val, inb);
   add_data(inb, sizeof(inb));
   }

}
/*
* SCAN Name Abstraction
* (C) 2008-2009,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

std::string make_arg(const std::vector<std::pair<size_t, std::string>>& name, size_t start)
   {
   std::string output = name[start].second;
   size_t level = name[start].first;

   size_t paren_depth = 0;

   for(size_t i = start + 1; i != name.size(); ++i)
      {
      if(name[i].first <= name[start].first)
         break;

      if(name[i].first > level)
         {
         output += "(" + name[i].second;
         ++paren_depth;
         }
      else if(name[i].first < level)
         {
         output += ")," + name[i].second;
         --paren_depth;
         }
      else
         {
         if(output[output.size() - 1] != '(')
            output += ",";
         output += name[i].second;
         }

      level = name[i].first;
      }

   for(size_t i = 0; i != paren_depth; ++i)
      output += ")";

   return output;
   }

}

SCAN_Name::SCAN_Name(const char* algo_spec) : SCAN_Name(std::string(algo_spec))
   {
   }

SCAN_Name::SCAN_Name(std::string algo_spec) : m_orig_algo_spec(algo_spec), m_alg_name(), m_args(), m_mode_info()
   {
   if(algo_spec.size() == 0)
      throw Invalid_Argument("Expected algorithm name, got empty string");

   std::vector<std::pair<size_t, std::string>> name;
   size_t level = 0;
   std::pair<size_t, std::string> accum = std::make_pair(level, "");

   const std::string decoding_error = "Bad SCAN name '" + algo_spec + "': ";

   for(size_t i = 0; i != algo_spec.size(); ++i)
      {
      char c = algo_spec[i];

      if(c == '/' || c == ',' || c == '(' || c == ')')
         {
         if(c == '(')
            ++level;
         else if(c == ')')
            {
            if(level == 0)
               throw Decoding_Error(decoding_error + "Mismatched parens");
            --level;
            }

         if(c == '/' && level > 0)
            accum.second.push_back(c);
         else
            {
            if(accum.second != "")
               name.push_back(accum);
            accum = std::make_pair(level, "");
            }
         }
      else
         accum.second.push_back(c);
      }

   if(accum.second != "")
      name.push_back(accum);

   if(level != 0)
      throw Decoding_Error(decoding_error + "Missing close paren");

   if(name.size() == 0)
      throw Decoding_Error(decoding_error + "Empty name");

   m_alg_name = name[0].second;

   bool in_modes = false;

   for(size_t i = 1; i != name.size(); ++i)
      {
      if(name[i].first == 0)
         {
         m_mode_info.push_back(make_arg(name, i));
         in_modes = true;
         }
      else if(name[i].first == 1 && !in_modes)
         m_args.push_back(make_arg(name, i));
      }
   }

std::string SCAN_Name::arg(size_t i) const
   {
   if(i >= arg_count())
      throw Invalid_Argument("SCAN_Name::arg " + std::to_string(i) +
                             " out of range for '" + to_string() + "'");
   return m_args[i];
   }

std::string SCAN_Name::arg(size_t i, const std::string& def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return m_args[i];
   }

size_t SCAN_Name::arg_as_integer(size_t i, size_t def_value) const
   {
   if(i >= arg_count())
      return def_value;
   return to_u32bit(m_args[i]);
   }

}
/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

void SymmetricAlgorithm::throw_key_not_set_error() const
   {
   throw Key_Not_Set(name());
   }

void SymmetricAlgorithm::set_key(const uint8_t key[], size_t length)
   {
   if(!valid_keylength(length))
      throw Invalid_Key_Length(name(), length);
   key_schedule(key, length);
   }

}
/*
* OctetString
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Create an OctetString from RNG output
*/
OctetString::OctetString(RandomNumberGenerator& rng,
                         size_t len)
   {
   rng.random_vec(m_data, len);
   }

/*
* Create an OctetString from a hex string
*/
OctetString::OctetString(const std::string& hex_string)
   {
   if(!hex_string.empty())
      {
      m_data.resize(1 + hex_string.length() / 2);
      m_data.resize(hex_decode(m_data.data(), hex_string));
      }
   }

/*
* Create an OctetString from a byte string
*/
OctetString::OctetString(const uint8_t in[], size_t n)
   {
   m_data.assign(in, in + n);
   }

/*
* Set the parity of each key byte to odd
*/
void OctetString::set_odd_parity()
   {
   const uint8_t ODD_PARITY[256] = {
      0x01, 0x01, 0x02, 0x02, 0x04, 0x04, 0x07, 0x07, 0x08, 0x08, 0x0B, 0x0B,
      0x0D, 0x0D, 0x0E, 0x0E, 0x10, 0x10, 0x13, 0x13, 0x15, 0x15, 0x16, 0x16,
      0x19, 0x19, 0x1A, 0x1A, 0x1C, 0x1C, 0x1F, 0x1F, 0x20, 0x20, 0x23, 0x23,
      0x25, 0x25, 0x26, 0x26, 0x29, 0x29, 0x2A, 0x2A, 0x2C, 0x2C, 0x2F, 0x2F,
      0x31, 0x31, 0x32, 0x32, 0x34, 0x34, 0x37, 0x37, 0x38, 0x38, 0x3B, 0x3B,
      0x3D, 0x3D, 0x3E, 0x3E, 0x40, 0x40, 0x43, 0x43, 0x45, 0x45, 0x46, 0x46,
      0x49, 0x49, 0x4A, 0x4A, 0x4C, 0x4C, 0x4F, 0x4F, 0x51, 0x51, 0x52, 0x52,
      0x54, 0x54, 0x57, 0x57, 0x58, 0x58, 0x5B, 0x5B, 0x5D, 0x5D, 0x5E, 0x5E,
      0x61, 0x61, 0x62, 0x62, 0x64, 0x64, 0x67, 0x67, 0x68, 0x68, 0x6B, 0x6B,
      0x6D, 0x6D, 0x6E, 0x6E, 0x70, 0x70, 0x73, 0x73, 0x75, 0x75, 0x76, 0x76,
      0x79, 0x79, 0x7A, 0x7A, 0x7C, 0x7C, 0x7F, 0x7F, 0x80, 0x80, 0x83, 0x83,
      0x85, 0x85, 0x86, 0x86, 0x89, 0x89, 0x8A, 0x8A, 0x8C, 0x8C, 0x8F, 0x8F,
      0x91, 0x91, 0x92, 0x92, 0x94, 0x94, 0x97, 0x97, 0x98, 0x98, 0x9B, 0x9B,
      0x9D, 0x9D, 0x9E, 0x9E, 0xA1, 0xA1, 0xA2, 0xA2, 0xA4, 0xA4, 0xA7, 0xA7,
      0xA8, 0xA8, 0xAB, 0xAB, 0xAD, 0xAD, 0xAE, 0xAE, 0xB0, 0xB0, 0xB3, 0xB3,
      0xB5, 0xB5, 0xB6, 0xB6, 0xB9, 0xB9, 0xBA, 0xBA, 0xBC, 0xBC, 0xBF, 0xBF,
      0xC1, 0xC1, 0xC2, 0xC2, 0xC4, 0xC4, 0xC7, 0xC7, 0xC8, 0xC8, 0xCB, 0xCB,
      0xCD, 0xCD, 0xCE, 0xCE, 0xD0, 0xD0, 0xD3, 0xD3, 0xD5, 0xD5, 0xD6, 0xD6,
      0xD9, 0xD9, 0xDA, 0xDA, 0xDC, 0xDC, 0xDF, 0xDF, 0xE0, 0xE0, 0xE3, 0xE3,
      0xE5, 0xE5, 0xE6, 0xE6, 0xE9, 0xE9, 0xEA, 0xEA, 0xEC, 0xEC, 0xEF, 0xEF,
      0xF1, 0xF1, 0xF2, 0xF2, 0xF4, 0xF4, 0xF7, 0xF7, 0xF8, 0xF8, 0xFB, 0xFB,
      0xFD, 0xFD, 0xFE, 0xFE };

   for(size_t j = 0; j != m_data.size(); ++j)
      m_data[j] = ODD_PARITY[m_data[j]];
   }

/*
* Hex encode an OctetString
*/
std::string OctetString::to_string() const
   {
   return hex_encode(m_data.data(), m_data.size());
   }

/*
* XOR Operation for OctetStrings
*/
OctetString& OctetString::operator^=(const OctetString& k)
   {
   if(&k == this) { zeroise(m_data); return (*this); }
   xor_buf(m_data.data(), k.begin(), std::min(length(), k.length()));
   return (*this);
   }

/*
* Equality Operation for OctetStrings
*/
bool operator==(const OctetString& s1, const OctetString& s2)
   {
   return (s1.bits_of() == s2.bits_of());
   }

/*
* Unequality Operation for OctetStrings
*/
bool operator!=(const OctetString& s1, const OctetString& s2)
   {
   return !(s1 == s2);
   }

/*
* Append Operation for OctetStrings
*/
OctetString operator+(const OctetString& k1, const OctetString& k2)
   {
   secure_vector<uint8_t> out;
   out += k1.bits_of();
   out += k2.bits_of();
   return OctetString(out);
   }

/*
* XOR Operation for OctetStrings
*/
OctetString operator^(const OctetString& k1, const OctetString& k2)
   {
   secure_vector<uint8_t> out(std::max(k1.length(), k2.length()));

   copy_mem(out.data(), k1.begin(), k1.length());
   xor_buf(out.data(), k2.begin(), k2.length());
   return OctetString(out);
   }

}
/*
* Base64 Encoding and Decoding
* (C) 2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

class Base64 final
   {
   public:
      static inline std::string name() noexcept
         {
         return "base64";
         }

      static inline size_t encoding_bytes_in() noexcept
         {
         return m_encoding_bytes_in;
         }
      static inline size_t encoding_bytes_out() noexcept
         {
         return m_encoding_bytes_out;
         }

      static inline size_t decoding_bytes_in() noexcept
         {
         return m_encoding_bytes_out;
         }
      static inline size_t decoding_bytes_out() noexcept
         {
         return m_encoding_bytes_in;
         }

      static inline size_t bits_consumed() noexcept
         {
         return m_encoding_bits;
         }
      static inline size_t remaining_bits_before_padding() noexcept
         {
         return m_remaining_bits_before_padding;
         }

      static inline size_t encode_max_output(size_t input_length)
         {
         return (round_up(input_length, m_encoding_bytes_in) / m_encoding_bytes_in) * m_encoding_bytes_out;
         }
      static inline size_t decode_max_output(size_t input_length)
         {
         return (round_up(input_length, m_encoding_bytes_out) * m_encoding_bytes_in) / m_encoding_bytes_out;
         }

      static void encode(char out[8], const uint8_t in[5]) noexcept
         {
         out[0] = Base64::m_bin_to_base64[(in[0] & 0xFC) >> 2];
         out[1] = Base64::m_bin_to_base64[((in[0] & 0x03) << 4) | (in[1] >> 4)];
         out[2] = Base64::m_bin_to_base64[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
         out[3] = Base64::m_bin_to_base64[in[2] & 0x3F];
         }

      static inline uint8_t lookup_binary_value(char input) noexcept
         {
         return Base64::m_base64_to_bin[static_cast<uint8_t>(input)];
         }

      static inline bool check_bad_char(uint8_t bin, char input, bool ignore_ws)
         {
         if(bin <= 0x3F)
            {
            return true;
            }
         else if(!(bin == 0x81 || (bin == 0x80 && ignore_ws)))
            {
            std::string bad_char(1, input);
            if(bad_char == "\t")
               { bad_char = "\\t"; }
            else if(bad_char == "\n")
               { bad_char = "\\n"; }
            else if(bad_char == "\r")
               { bad_char = "\\r"; }

            throw Invalid_Argument(
               std::string("base64_decode: invalid base64 character '") +
               bad_char + "'");
            }
         return false;
         }

      static void decode(uint8_t* out_ptr, const uint8_t decode_buf[4])
         {
         out_ptr[0] = (decode_buf[0] << 2) | (decode_buf[1] >> 4);
         out_ptr[1] = (decode_buf[1] << 4) | (decode_buf[2] >> 2);
         out_ptr[2] = (decode_buf[2] << 6) | decode_buf[3];
         }

      static inline size_t bytes_to_remove(size_t final_truncate)
         {
         return final_truncate;
         }

   private:
      static const size_t m_encoding_bits = 6;
      static const size_t m_remaining_bits_before_padding = 8;


      static const size_t m_encoding_bytes_in = 3;
      static const size_t m_encoding_bytes_out = 4;


      static const uint8_t m_bin_to_base64[64];
      static const uint8_t m_base64_to_bin[256];
   };

const uint8_t Base64::m_bin_to_base64[64] =
   {
   'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
   'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
   'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
   'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
   '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
   };

/*
* base64 Decoder Lookup Table
* Warning: assumes ASCII encodings
*/
const uint8_t Base64::m_base64_to_bin[256] =
   {
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
   0x80, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F, 0x34, 0x35,
   0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF,
   0xFF, 0x81, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04,
   0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
   0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
   0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1A, 0x1B, 0x1C,
   0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
   0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
   0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
   };
}

size_t base64_encode(char out[],
                     const uint8_t in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs)
   {
   return base_encode(Base64(), out, in, input_length, input_consumed, final_inputs);
   }

std::string base64_encode(const uint8_t input[],
                          size_t input_length)
   {
   return base_encode_to_string(Base64(), input, input_length);
   }

size_t base64_decode(uint8_t out[],
                     const char in[],
                     size_t input_length,
                     size_t& input_consumed,
                     bool final_inputs,
                     bool ignore_ws)
   {
   return base_decode(Base64(), out, in, input_length, input_consumed, final_inputs, ignore_ws);
   }

size_t base64_decode(uint8_t output[],
                     const char input[],
                     size_t input_length,
                     bool ignore_ws)
   {
   return base_decode_full(Base64(), output, input, input_length, ignore_ws);
   }

size_t base64_decode(uint8_t output[],
                     const std::string& input,
                     bool ignore_ws)
   {
   return base64_decode(output, input.data(), input.length(), ignore_ws);
   }

secure_vector<uint8_t> base64_decode(const char input[],
                                     size_t input_length,
                                     bool ignore_ws)
   {
   return base_decode_to_vec<secure_vector<uint8_t>>(Base64(), input, input_length, ignore_ws);
   }

secure_vector<uint8_t> base64_decode(const std::string& input,
                                     bool ignore_ws)
   {
   return base64_decode(input.data(), input.size(), ignore_ws);
   }

size_t base64_encode_max_output(size_t input_length)
   {
   return Base64::encode_max_output(input_length);
   }

size_t base64_decode_max_output(size_t input_length)
   {
   return Base64::decode_max_output(input_length);
   }

}
/*
* Block Ciphers
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_AES)
#endif

#if defined(BOTAN_HAS_ARIA)
#endif

#if defined(BOTAN_HAS_BLOWFISH)
#endif

#if defined(BOTAN_HAS_CAMELLIA)
#endif

#if defined(BOTAN_HAS_CAST_128)
#endif

#if defined(BOTAN_HAS_CAST_256)
#endif

#if defined(BOTAN_HAS_CASCADE)
#endif

#if defined(BOTAN_HAS_DES)
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
#endif

#if defined(BOTAN_HAS_IDEA)
#endif

#if defined(BOTAN_HAS_KASUMI)
#endif

#if defined(BOTAN_HAS_LION)
#endif

#if defined(BOTAN_HAS_MISTY1)
#endif

#if defined(BOTAN_HAS_NOEKEON)
#endif

#if defined(BOTAN_HAS_SEED)
#endif

#if defined(BOTAN_HAS_SERPENT)
#endif

#if defined(BOTAN_HAS_SHACAL2)
#endif

#if defined(BOTAN_HAS_SM4)
#endif

#if defined(BOTAN_HAS_TWOFISH)
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
#endif

#if defined(BOTAN_HAS_XTEA)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
#endif

namespace Botan {

std::unique_ptr<BlockCipher>
BlockCipher::create(const std::string& algo,
                    const std::string& provider)
   {
#if defined(BOTAN_HAS_COMMONCRYPTO)
   if(provider.empty() || provider == "commoncrypto")
      {
      if(auto bc = make_commoncrypto_block_cipher(algo))
         return bc;

      if(!provider.empty())
         return nullptr;
      }
#endif

#if defined(BOTAN_HAS_OPENSSL)
   if(provider.empty() || provider == "openssl")
      {
      if(auto bc = make_openssl_block_cipher(algo))
         return bc;

      if(!provider.empty())
         return nullptr;
      }
#endif

   // TODO: CryptoAPI
   // TODO: /dev/crypto

   // Only base providers from here on out
   if(provider.empty() == false && provider != "base")
      return nullptr;

#if defined(BOTAN_HAS_AES)
   if(algo == "AES-128")
      {
      return std::unique_ptr<BlockCipher>(new AES_128);
      }

   if(algo == "AES-192")
      {
      return std::unique_ptr<BlockCipher>(new AES_192);
      }

   if(algo == "AES-256")
      {
      return std::unique_ptr<BlockCipher>(new AES_256);
      }
#endif

#if defined(BOTAN_HAS_ARIA)
   if(algo == "ARIA-128")
      {
      return std::unique_ptr<BlockCipher>(new ARIA_128);
      }

   if(algo == "ARIA-192")
      {
      return std::unique_ptr<BlockCipher>(new ARIA_192);
      }

   if(algo == "ARIA-256")
      {
      return std::unique_ptr<BlockCipher>(new ARIA_256);
      }
#endif

#if defined(BOTAN_HAS_SERPENT)
   if(algo == "Serpent")
      {
      return std::unique_ptr<BlockCipher>(new Serpent);
      }
#endif

#if defined(BOTAN_HAS_SHACAL2)
   if(algo == "SHACAL2")
      {
      return std::unique_ptr<BlockCipher>(new SHACAL2);
      }
#endif

#if defined(BOTAN_HAS_TWOFISH)
   if(algo == "Twofish")
      {
      return std::unique_ptr<BlockCipher>(new Twofish);
      }
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
   if(algo == "Threefish-512")
      {
      return std::unique_ptr<BlockCipher>(new Threefish_512);
      }
#endif

#if defined(BOTAN_HAS_BLOWFISH)
   if(algo == "Blowfish")
      {
      return std::unique_ptr<BlockCipher>(new Blowfish);
      }
#endif

#if defined(BOTAN_HAS_CAMELLIA)
   if(algo == "Camellia-128")
      {
      return std::unique_ptr<BlockCipher>(new Camellia_128);
      }

   if(algo == "Camellia-192")
      {
      return std::unique_ptr<BlockCipher>(new Camellia_192);
      }

   if(algo == "Camellia-256")
      {
      return std::unique_ptr<BlockCipher>(new Camellia_256);
      }
#endif

#if defined(BOTAN_HAS_DES)
   if(algo == "DES")
      {
      return std::unique_ptr<BlockCipher>(new DES);
      }

   if(algo == "DESX")
      {
      return std::unique_ptr<BlockCipher>(new DESX);
      }

   if(algo == "TripleDES" || algo == "3DES" || algo == "DES-EDE")
      {
      return std::unique_ptr<BlockCipher>(new TripleDES);
      }
#endif

#if defined(BOTAN_HAS_NOEKEON)
   if(algo == "Noekeon")
      {
      return std::unique_ptr<BlockCipher>(new Noekeon);
      }
#endif

#if defined(BOTAN_HAS_CAST_128)
   if(algo == "CAST-128" || algo == "CAST5")
      {
      return std::unique_ptr<BlockCipher>(new CAST_128);
      }
#endif

#if defined(BOTAN_HAS_CAST_256)
   if(algo == "CAST-256")
      {
      return std::unique_ptr<BlockCipher>(new CAST_256);
      }
#endif

#if defined(BOTAN_HAS_IDEA)
   if(algo == "IDEA")
      {
      return std::unique_ptr<BlockCipher>(new IDEA);
      }
#endif

#if defined(BOTAN_HAS_KASUMI)
   if(algo == "KASUMI")
      {
      return std::unique_ptr<BlockCipher>(new KASUMI);
      }
#endif

#if defined(BOTAN_HAS_MISTY1)
   if(algo == "MISTY1")
      {
      return std::unique_ptr<BlockCipher>(new MISTY1);
      }
#endif

#if defined(BOTAN_HAS_SEED)
   if(algo == "SEED")
      {
      return std::unique_ptr<BlockCipher>(new SEED);
      }
#endif

#if defined(BOTAN_HAS_SM4)
   if(algo == "SM4")
      {
      return std::unique_ptr<BlockCipher>(new SM4);
      }
#endif

#if defined(BOTAN_HAS_XTEA)
   if(algo == "XTEA")
      {
      return std::unique_ptr<BlockCipher>(new XTEA);
      }
#endif

   const SCAN_Name req(algo);

#if defined(BOTAN_HAS_GOST_28147_89)
   if(req.algo_name() == "GOST-28147-89")
      {
      return std::unique_ptr<BlockCipher>(new GOST_28147_89(req.arg(0, "R3411_94_TestParam")));
      }
#endif

#if defined(BOTAN_HAS_CASCADE)
   if(req.algo_name() == "Cascade" && req.arg_count() == 2)
      {
      std::unique_ptr<BlockCipher> c1(BlockCipher::create(req.arg(0)));
      std::unique_ptr<BlockCipher> c2(BlockCipher::create(req.arg(1)));

      if(c1 && c2)
         return std::unique_ptr<BlockCipher>(new Cascade_Cipher(c1.release(), c2.release()));
      }
#endif

#if defined(BOTAN_HAS_LION)
   if(req.algo_name() == "Lion" && req.arg_count_between(2, 3))
      {
      std::unique_ptr<HashFunction> hash(HashFunction::create(req.arg(0)));
      std::unique_ptr<StreamCipher> stream(StreamCipher::create(req.arg(1)));

      if(hash && stream)
         {
         const size_t block_size = req.arg_as_integer(2, 1024);
         return std::unique_ptr<BlockCipher>(new Lion(hash.release(), stream.release(), block_size));
         }
      }
#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<BlockCipher>
BlockCipher::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto bc = BlockCipher::create(algo, provider))
      {
      return bc;
      }
   throw Lookup_Error("Block cipher", algo, provider);
   }

std::vector<std::string> BlockCipher::providers(const std::string& algo)
   {
   return probe_providers_of<BlockCipher>(algo, { "base", "openssl", "commoncrypto" });
   }

}
/*
* Runtime CPU detection
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <ostream>

namespace Botan {

bool CPUID::has_simd_32()
   {
#if defined(BOTAN_TARGET_SUPPORTS_SSE2)
   return CPUID::has_sse2();
#elif defined(BOTAN_TARGET_SUPPORTS_ALTIVEC)
   return CPUID::has_altivec();
#elif defined(BOTAN_TARGET_SUPPORTS_NEON)
   return CPUID::has_neon();
#else
   return true;
#endif
   }

//static
std::string CPUID::to_string()
   {
   std::vector<std::string> flags;

#define CPUID_PRINT(flag) do { if(has_##flag()) { flags.push_back(#flag); } } while(0)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   CPUID_PRINT(sse2);
   CPUID_PRINT(ssse3);
   CPUID_PRINT(sse41);
   CPUID_PRINT(sse42);
   CPUID_PRINT(avx2);
   CPUID_PRINT(avx512f);

   CPUID_PRINT(rdtsc);
   CPUID_PRINT(bmi1);
   CPUID_PRINT(bmi2);
   CPUID_PRINT(adx);

   CPUID_PRINT(aes_ni);
   CPUID_PRINT(clmul);
   CPUID_PRINT(rdrand);
   CPUID_PRINT(rdseed);
   CPUID_PRINT(intel_sha);
#endif

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   CPUID_PRINT(altivec);
   CPUID_PRINT(ppc_crypto);
   CPUID_PRINT(darn_rng);
#endif

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   CPUID_PRINT(neon);
   CPUID_PRINT(arm_sve);

   CPUID_PRINT(arm_sha1);
   CPUID_PRINT(arm_sha2);
   CPUID_PRINT(arm_aes);
   CPUID_PRINT(arm_pmull);
   CPUID_PRINT(arm_sha2_512);
   CPUID_PRINT(arm_sha3);
   CPUID_PRINT(arm_sm3);
   CPUID_PRINT(arm_sm4);
#endif

#undef CPUID_PRINT

   return string_join(flags, ' ');
   }

//static
void CPUID::print(std::ostream& o)
   {
   o << "CPUID flags: " << CPUID::to_string() << "\n";
   }

//static
void CPUID::initialize()
   {
   state() = CPUID_Data();
   }

CPUID::CPUID_Data::CPUID_Data()
   {
#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY) || \
    defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   m_cache_line_size = 0;
   m_processor_features = detect_cpu_features(&m_cache_line_size);

#endif

   m_processor_features |= CPUID::CPUID_INITIALIZED_BIT;

   if(m_cache_line_size == 0)
      m_cache_line_size = BOTAN_TARGET_CPU_DEFAULT_CACHE_LINE_SIZE;

   m_endian_status = runtime_check_endian();
   }

//static
CPUID::Endian_Status CPUID::CPUID_Data::runtime_check_endian()
   {
   // Check runtime endian
   const uint32_t endian32 = 0x01234567;
   const uint8_t* e8 = reinterpret_cast<const uint8_t*>(&endian32);

   CPUID::Endian_Status endian = CPUID::Endian_Status::Unknown;

   if(e8[0] == 0x01 && e8[1] == 0x23 && e8[2] == 0x45 && e8[3] == 0x67)
      {
      endian = CPUID::Endian_Status::Big;
      }
   else if(e8[0] == 0x67 && e8[1] == 0x45 && e8[2] == 0x23 && e8[3] == 0x01)
      {
      endian = CPUID::Endian_Status::Little;
      }
   else
      {
      throw Internal_Error("Unexpected endian at runtime, neither big nor little");
      }

   // If we were compiled with a known endian, verify it matches at runtime
#if defined(BOTAN_TARGET_CPU_IS_LITTLE_ENDIAN)
   BOTAN_ASSERT(endian == CPUID::Endian_Status::Little, "Build and runtime endian match");
#elif defined(BOTAN_TARGET_CPU_IS_BIG_ENDIAN)
   BOTAN_ASSERT(endian == CPUID::Endian_Status::Big, "Build and runtime endian match");
#endif

   return endian;
   }

std::vector<Botan::CPUID::CPUID_bits>
CPUID::bit_from_string(const std::string& tok)
   {
#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)
   if(tok == "sse2" || tok == "simd")
      return {Botan::CPUID::CPUID_SSE2_BIT};
   if(tok == "ssse3")
      return {Botan::CPUID::CPUID_SSSE3_BIT};
   if(tok == "aesni")
      return {Botan::CPUID::CPUID_AESNI_BIT};
   if(tok == "clmul")
      return {Botan::CPUID::CPUID_CLMUL_BIT};
   if(tok == "avx2")
      return {Botan::CPUID::CPUID_AVX2_BIT};
   if(tok == "sha")
      return {Botan::CPUID::CPUID_SHA_BIT};
   if(tok == "bmi2")
      return {Botan::CPUID::CPUID_BMI2_BIT};
   if(tok == "adx")
      return {Botan::CPUID::CPUID_ADX_BIT};
   if(tok == "intel_sha")
      return {Botan::CPUID::CPUID_SHA_BIT};

#elif defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)
   if(tok == "altivec" || tok == "simd")
      return {Botan::CPUID::CPUID_ALTIVEC_BIT};
   if(tok == "ppc_crypto")
      return {Botan::CPUID::CPUID_PPC_CRYPTO_BIT};

#elif defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)
   if(tok == "neon" || tok == "simd")
      return {Botan::CPUID::CPUID_ARM_NEON_BIT};
   if(tok == "armv8sha1")
      return {Botan::CPUID::CPUID_ARM_SHA1_BIT};
   if(tok == "armv8sha2")
      return {Botan::CPUID::CPUID_ARM_SHA2_BIT};
   if(tok == "armv8aes")
      return {Botan::CPUID::CPUID_ARM_AES_BIT};
   if(tok == "armv8pmull")
      return {Botan::CPUID::CPUID_ARM_PMULL_BIT};
   if(tok == "armv8sha3")
      return {Botan::CPUID::CPUID_ARM_SHA3_BIT};
   if(tok == "armv8sha2_512")
      return {Botan::CPUID::CPUID_ARM_SHA2_512_BIT};
   if(tok == "armv8sm3")
      return {Botan::CPUID::CPUID_ARM_SM3_BIT};
   if(tok == "armv8sm4")
      return {Botan::CPUID::CPUID_ARM_SM4_BIT};

#else
   BOTAN_UNUSED(tok);
#endif

   return {};
   }

}
/*
* Runtime CPU detection for ARM
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)

#if defined(BOTAN_TARGET_OS_IS_IOS)
  #include <sys/types.h>
  #include <sys/sysctl.h>

#else

#endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_ARM_FAMILY)

#if defined(BOTAN_TARGET_OS_IS_IOS)

namespace {

uint64_t flags_by_ios_machine_type(const std::string& machine)
   {
   /*
   * This relies on a map of known machine names to features. This
   * will quickly grow out of date as new products are introduced, but
   * is apparently the best we can do for iOS.
   */

   struct version_info {
      std::string name;
      size_t min_version_neon;
      size_t min_version_armv8;
      };

   static const version_info min_versions[] = {
      { "iPhone", 2, 6 },
      { "iPad", 1, 4 },
      { "iPod", 4, 7 },
      { "AppleTV", 2, 5 },
   };

   if(machine.size() < 3)
      return 0;

   auto comma = machine.find(',');

   // Simulator, or something we don't know about
   if(comma == std::string::npos)
      return 0;

   std::string product = machine.substr(0, comma);

   size_t version = 0;
   size_t place = 1;
   while(product.size() > 1 && ::isdigit(product.back()))
      {
      const size_t digit = product.back() - '0';
      version += digit * place;
      place *= 10;
      product.pop_back();
      }

   if(version == 0)
      return 0;

   for(const version_info& info : min_versions)
      {
      if(info.name != product)
         continue;

      if(version >= info.min_version_armv8)
         {
         return CPUID::CPUID_ARM_AES_BIT |
                CPUID::CPUID_ARM_PMULL_BIT |
                CPUID::CPUID_ARM_SHA1_BIT |
                CPUID::CPUID_ARM_SHA2_BIT |
                CPUID::CPUID_ARM_NEON_BIT;
         }

      if(version >= info.min_version_neon)
         return CPUID::CPUID_ARM_NEON_BIT;
      }

   // Some other product we don't know about
   return 0;
   }

}

#endif

uint64_t CPUID::CPUID_Data::detect_cpu_features(size_t* cache_line_size)
   {
   uint64_t detected_features = 0;

#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   /*
   * On systems with getauxval these bits should normally be defined
   * in bits/auxv.h but some buggy? glibc installs seem to miss them.
   * These following values are all fixed, for the Linux ELF format,
   * so we just hardcode them in ARM_hwcap_bit enum.
   */

   enum ARM_hwcap_bit {
#if defined(BOTAN_TARGET_ARCH_IS_ARM32)
      NEON_bit  = (1 << 12),
      AES_bit   = (1 << 0),
      PMULL_bit = (1 << 1),
      SHA1_bit  = (1 << 2),
      SHA2_bit  = (1 << 3),

      ARCH_hwcap_neon   = 16, // AT_HWCAP
      ARCH_hwcap_crypto = 26, // AT_HWCAP2
#elif defined(BOTAN_TARGET_ARCH_IS_ARM64)
      NEON_bit  = (1 << 1),
      AES_bit   = (1 << 3),
      PMULL_bit = (1 << 4),
      SHA1_bit  = (1 << 5),
      SHA2_bit  = (1 << 6),
      SHA3_bit  = (1 << 17),
      SM3_bit  = (1 << 18),
      SM4_bit  = (1 << 19),
      SHA2_512_bit  = (1 << 21),
      SVE_bit = (1 << 22),

      ARCH_hwcap_neon   = 16, // AT_HWCAP
      ARCH_hwcap_crypto = 16, // AT_HWCAP
#endif
   };

#if defined(AT_DCACHEBSIZE)
   // Exists only on Linux
   const unsigned long dcache_line = ::getauxval(AT_DCACHEBSIZE);

   // plausibility check
   if(dcache_line == 32 || dcache_line == 64 || dcache_line == 128)
      *cache_line_size = static_cast<size_t>(dcache_line);
#endif

   const unsigned long hwcap_neon = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap_neon);
   if(hwcap_neon & ARM_hwcap_bit::NEON_bit)
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

   /*
   On aarch64 this ends up calling getauxval twice with AT_HWCAP
   It doesn't seem worth optimizing this out, since getauxval is
   just reading a field in the ELF header.
   */
   const unsigned long hwcap_crypto = OS::get_auxval(ARM_hwcap_bit::ARCH_hwcap_crypto);
   if(hwcap_crypto & ARM_hwcap_bit::AES_bit)
      detected_features |= CPUID::CPUID_ARM_AES_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::PMULL_bit)
      detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SHA1_bit)
      detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SHA2_bit)
      detected_features |= CPUID::CPUID_ARM_SHA2_BIT;

#if defined(BOTAN_TARGET_ARCH_IS_ARM64)
   if(hwcap_crypto & ARM_hwcap_bit::SHA3_bit)
      detected_features |= CPUID::CPUID_ARM_SHA3_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SM3_bit)
      detected_features |= CPUID::CPUID_ARM_SM3_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SM4_bit)
      detected_features |= CPUID::CPUID_ARM_SM4_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SHA2_512_bit)
      detected_features |= CPUID::CPUID_ARM_SHA2_512_BIT;
   if(hwcap_crypto & ARM_hwcap_bit::SVE_bit)
      detected_features |= CPUID::CPUID_ARM_SVE_BIT;
#endif

#elif defined(BOTAN_TARGET_OS_IS_IOS)

   char machine[64] = { 0 };
   size_t size = sizeof(machine) - 1;
   ::sysctlbyname("hw.machine", machine, &size, nullptr, 0);

   detected_features = flags_by_ios_machine_type(machine);

#elif defined(BOTAN_USE_GCC_INLINE_ASM) && defined(BOTAN_TARGET_ARCH_IS_ARM64)

   /*
   No getauxval API available, fall back on probe functions. We only
   bother with Aarch64 here to simplify the code and because going to
   extreme contortions to support detect NEON on devices that probably
   don't support it doesn't seem worthwhile.

   NEON registers v0-v7 are caller saved in Aarch64
   */

   auto neon_probe  = []() -> int { asm("and v0.16b, v0.16b, v0.16b"); return 1; };
   auto aes_probe   = []() -> int { asm(".word 0x4e284800"); return 1; };
   auto pmull_probe = []() -> int { asm(".word 0x0ee0e000"); return 1; };
   auto sha1_probe  = []() -> int { asm(".word 0x5e280800"); return 1; };
   auto sha2_probe  = []() -> int { asm(".word 0x5e282800"); return 1; };

   // Only bother running the crypto detection if we found NEON

   if(OS::run_cpu_instruction_probe(neon_probe) == 1)
      {
      detected_features |= CPUID::CPUID_ARM_NEON_BIT;

      if(OS::run_cpu_instruction_probe(aes_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_AES_BIT;
      if(OS::run_cpu_instruction_probe(pmull_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_PMULL_BIT;
      if(OS::run_cpu_instruction_probe(sha1_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA1_BIT;
      if(OS::run_cpu_instruction_probe(sha2_probe) == 1)
         detected_features |= CPUID::CPUID_ARM_SHA2_BIT;
      }

#endif

   return detected_features;
   }

#endif

}
/*
* Runtime CPU detection for POWER/PowerPC
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

/*
* On macOS and OpenBSD ppc, use sysctl to detect AltiVec
*/
#if defined(BOTAN_TARGET_OS_IS_MACOS)
  #include <sys/sysctl.h>
#elif defined(BOTAN_TARGET_OS_IS_OPENBSD)
  #include <sys/param.h>
  #include <sys/sysctl.h>
  #include <machine/cpu.h>
#endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_PPC_FAMILY)

/*
* PowerPC specific block: check for AltiVec using either
* sysctl or by reading processor version number register.
*/
uint64_t CPUID::CPUID_Data::detect_cpu_features(size_t* cache_line_size)
   {
   BOTAN_UNUSED(cache_line_size);

#if defined(BOTAN_TARGET_OS_IS_MACOS) || defined(BOTAN_TARGET_OS_IS_OPENBSD)
   // On macOS and OpenBSD, use sysctl

   int sels[2] = {
#if defined(BOTAN_TARGET_OS_IS_OPENBSD)
      CTL_MACHDEP, CPU_ALTIVEC
#else
      CTL_HW, HW_VECTORUNIT
#endif
   };

   int vector_type = 0;
   size_t length = sizeof(vector_type);
   int error = ::sysctl(sels, 2, &vector_type, &length, NULL, 0);

   if(error == 0 && vector_type > 0)
      return CPUID::CPUID_ALTIVEC_BIT;

#elif (defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_HAS_ELF_AUX_INFO)) && defined(BOTAN_TARGET_ARCH_IS_PPC64)

   enum PPC_hwcap_bit {
      ALTIVEC_bit  = (1 << 28),
      CRYPTO_bit   = (1 << 25),
      DARN_bit     = (1 << 21),

      ARCH_hwcap_altivec = 16, // AT_HWCAP
      ARCH_hwcap_crypto  = 26, // AT_HWCAP2
   };

   uint64_t detected_features = 0;

   const unsigned long hwcap_altivec = OS::get_auxval(PPC_hwcap_bit::ARCH_hwcap_altivec);
   if(hwcap_altivec & PPC_hwcap_bit::ALTIVEC_bit)
      detected_features |= CPUID::CPUID_ALTIVEC_BIT;

   const unsigned long hwcap_crypto = OS::get_auxval(PPC_hwcap_bit::ARCH_hwcap_crypto);
   if(hwcap_crypto & PPC_hwcap_bit::CRYPTO_bit)
     detected_features |= CPUID::CPUID_PPC_CRYPTO_BIT;
   if(hwcap_crypto & PPC_hwcap_bit::DARN_bit)
     detected_features |= CPUID::CPUID_DARN_BIT;

   return detected_features;

#else

   /*
   On PowerPC, MSR 287 is PVR, the Processor Version Number
   Normally it is only accessible to ring 0, but Linux and NetBSD
   (others, too, maybe?) will trap and emulate it for us.
   */

   int pvr = OS::run_cpu_instruction_probe([]() -> int {
      uint32_t pvr = 0;
      asm volatile("mfspr %0, 287" : "=r" (pvr));
      // Top 16 bits suffice to identify the model
      return static_cast<int>(pvr >> 16);
      });

   if(pvr > 0)
      {
      const uint16_t ALTIVEC_PVR[] = {
         0x003E, // IBM POWER6
         0x003F, // IBM POWER7
         0x004A, // IBM POWER7p
         0x004B, // IBM POWER8E
         0x004C, // IBM POWER8 NVL
         0x004D, // IBM POWER8
         0x004E, // IBM POWER9
         0x000C, // G4-7400
         0x0039, // G5 970
         0x003C, // G5 970FX
         0x0044, // G5 970MP
         0x0070, // Cell PPU
         0, // end
      };

      for(size_t i = 0; ALTIVEC_PVR[i]; ++i)
         {
         if(pvr == ALTIVEC_PVR[i])
            return CPUID::CPUID_ALTIVEC_BIT;
         }

      return 0;
      }

   // TODO try direct instruction probing

#endif

   return 0;
   }

#endif

}
/*
* Runtime CPU detection for x86
* (C) 2009,2010,2013,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #include <intrin.h>
#elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)
  #include <ia32intrin.h>
#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
  #include <cpuid.h>
#endif

#endif

namespace Botan {

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

uint64_t CPUID::CPUID_Data::detect_cpu_features(size_t* cache_line_size)
   {
#if defined(BOTAN_BUILD_COMPILER_IS_MSVC)
  #define X86_CPUID(type, out) do { __cpuid((int*)out, type); } while(0)
  #define X86_CPUID_SUBLEVEL(type, level, out) do { __cpuidex((int*)out, type, level); } while(0)

#elif defined(BOTAN_BUILD_COMPILER_IS_INTEL)
  #define X86_CPUID(type, out) do { __cpuid(out, type); } while(0)
  #define X86_CPUID_SUBLEVEL(type, level, out) do { __cpuidex((int*)out, type, level); } while(0)

#elif defined(BOTAN_TARGET_ARCH_IS_X86_64) && defined(BOTAN_USE_GCC_INLINE_ASM)
  #define X86_CPUID(type, out)                                                    \
     asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) \
         : "0" (type))

  #define X86_CPUID_SUBLEVEL(type, level, out)                                    \
     asm("cpuid\n\t" : "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]) \
         : "0" (type), "2" (level))

#elif defined(BOTAN_BUILD_COMPILER_IS_GCC) || defined(BOTAN_BUILD_COMPILER_IS_CLANG)
  #define X86_CPUID(type, out) do { __get_cpuid(type, out, out+1, out+2, out+3); } while(0)

  #define X86_CPUID_SUBLEVEL(type, level, out) \
     do { __cpuid_count(type, level, out[0], out[1], out[2], out[3]); } while(0)
#else
  #warning "No way of calling x86 cpuid instruction for this compiler"
  #define X86_CPUID(type, out) do { clear_mem(out, 4); } while(0)
  #define X86_CPUID_SUBLEVEL(type, level, out) do { clear_mem(out, 4); } while(0)
#endif

   uint64_t features_detected = 0;
   uint32_t cpuid[4] = { 0 };

   // CPUID 0: vendor identification, max sublevel
   X86_CPUID(0, cpuid);

   const uint32_t max_supported_sublevel = cpuid[0];

   const uint32_t INTEL_CPUID[3] = { 0x756E6547, 0x6C65746E, 0x49656E69 };
   const uint32_t AMD_CPUID[3] = { 0x68747541, 0x444D4163, 0x69746E65 };
   const bool is_intel = same_mem(cpuid + 1, INTEL_CPUID, 3);
   const bool is_amd = same_mem(cpuid + 1, AMD_CPUID, 3);

   if(max_supported_sublevel >= 1)
      {
      // CPUID 1: feature bits
      X86_CPUID(1, cpuid);
      const uint64_t flags0 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[3];

      enum x86_CPUID_1_bits : uint64_t {
         RDTSC = (1ULL << 4),
         SSE2 = (1ULL << 26),
         CLMUL = (1ULL << 33),
         SSSE3 = (1ULL << 41),
         SSE41 = (1ULL << 51),
         SSE42 = (1ULL << 52),
         AESNI = (1ULL << 57),
         RDRAND = (1ULL << 62)
      };

      if(flags0 & x86_CPUID_1_bits::RDTSC)
         features_detected |= CPUID::CPUID_RDTSC_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE2)
         features_detected |= CPUID::CPUID_SSE2_BIT;
      if(flags0 & x86_CPUID_1_bits::CLMUL)
         features_detected |= CPUID::CPUID_CLMUL_BIT;
      if(flags0 & x86_CPUID_1_bits::SSSE3)
         features_detected |= CPUID::CPUID_SSSE3_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE41)
         features_detected |= CPUID::CPUID_SSE41_BIT;
      if(flags0 & x86_CPUID_1_bits::SSE42)
         features_detected |= CPUID::CPUID_SSE42_BIT;
      if(flags0 & x86_CPUID_1_bits::AESNI)
         features_detected |= CPUID::CPUID_AESNI_BIT;
      if(flags0 & x86_CPUID_1_bits::RDRAND)
         features_detected |= CPUID::CPUID_RDRAND_BIT;
      }

   if(is_intel)
      {
      // Intel cache line size is in cpuid(1) output
      *cache_line_size = 8 * get_byte(2, cpuid[1]);
      }
   else if(is_amd)
      {
      // AMD puts it in vendor zone
      X86_CPUID(0x80000005, cpuid);
      *cache_line_size = get_byte(3, cpuid[2]);
      }

   if(max_supported_sublevel >= 7)
      {
      clear_mem(cpuid, 4);
      X86_CPUID_SUBLEVEL(7, 0, cpuid);

      enum x86_CPUID_7_bits : uint64_t {
         BMI1 = (1ULL << 3),
         AVX2 = (1ULL << 5),
         BMI2 = (1ULL << 8),
         AVX512F = (1ULL << 16),
         RDSEED = (1ULL << 18),
         ADX = (1ULL << 19),
         SHA = (1ULL << 29),
      };
      uint64_t flags7 = (static_cast<uint64_t>(cpuid[2]) << 32) | cpuid[1];

      if(flags7 & x86_CPUID_7_bits::AVX2)
         features_detected |= CPUID::CPUID_AVX2_BIT;
      if(flags7 & x86_CPUID_7_bits::BMI1)
         {
         features_detected |= CPUID::CPUID_BMI1_BIT;
         /*
         We only set the BMI2 bit if BMI1 is also supported, so BMI2
         code can safely use both extensions. No known processor
         implements BMI2 but not BMI1.
         */
         if(flags7 & x86_CPUID_7_bits::BMI2)
            features_detected |= CPUID::CPUID_BMI2_BIT;
         }

      if(flags7 & x86_CPUID_7_bits::AVX512F)
         features_detected |= CPUID::CPUID_AVX512F_BIT;
      if(flags7 & x86_CPUID_7_bits::RDSEED)
         features_detected |= CPUID::CPUID_RDSEED_BIT;
      if(flags7 & x86_CPUID_7_bits::ADX)
         features_detected |= CPUID::CPUID_ADX_BIT;
      if(flags7 & x86_CPUID_7_bits::SHA)
         features_detected |= CPUID::CPUID_SHA_BIT;
      }

#undef X86_CPUID
#undef X86_CPUID_SUBLEVEL

   /*
   * If we don't have access to CPUID, we can still safely assume that
   * any x86-64 processor has SSE2 and RDTSC
   */
#if defined(BOTAN_TARGET_ARCH_IS_X86_64)
   if(features_detected == 0)
      {
      features_detected |= CPUID::CPUID_SSE2_BIT;
      features_detected |= CPUID::CPUID_RDTSC_BIT;
      }
#endif

   return features_detected;
   }

#endif

}
/*
* Counter mode
* (C) 1999-2011,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

CTR_BE::CTR_BE(BlockCipher* ciph) :
   m_cipher(ciph),
   m_block_size(m_cipher->block_size()),
   m_ctr_size(m_block_size),
   m_ctr_blocks(m_cipher->parallel_bytes() / m_block_size),
   m_counter(m_cipher->parallel_bytes()),
   m_pad(m_counter.size()),
   m_pad_pos(0)
   {
   }

CTR_BE::CTR_BE(BlockCipher* cipher, size_t ctr_size) :
   m_cipher(cipher),
   m_block_size(m_cipher->block_size()),
   m_ctr_size(ctr_size),
   m_ctr_blocks(m_cipher->parallel_bytes() / m_block_size),
   m_counter(m_cipher->parallel_bytes()),
   m_pad(m_counter.size()),
   m_pad_pos(0)
   {
   BOTAN_ARG_CHECK(m_ctr_size >= 4 && m_ctr_size <= m_block_size,
                   "Invalid CTR-BE counter size");
   }

void CTR_BE::clear()
   {
   m_cipher->clear();
   zeroise(m_pad);
   zeroise(m_counter);
   zap(m_iv);
   m_pad_pos = 0;
   }

size_t CTR_BE::default_iv_length() const
   {
   return m_block_size;
   }

bool CTR_BE::valid_iv_length(size_t iv_len) const
   {
   return (iv_len <= m_block_size);
   }

Key_Length_Specification CTR_BE::key_spec() const
   {
   return m_cipher->key_spec();
   }

CTR_BE* CTR_BE::clone() const
   {
   return new CTR_BE(m_cipher->clone(), m_ctr_size);
   }

void CTR_BE::key_schedule(const uint8_t key[], size_t key_len)
   {
   m_cipher->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

std::string CTR_BE::name() const
   {
   if(m_ctr_size == m_block_size)
      return ("CTR-BE(" + m_cipher->name() + ")");
   else
      return ("CTR-BE(" + m_cipher->name() + "," + std::to_string(m_ctr_size) + ")");

   }

void CTR_BE::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   verify_key_set(m_iv.empty() == false);

   const uint8_t* pad_bits = &m_pad[0];
   const size_t pad_size = m_pad.size();

   if(m_pad_pos > 0)
      {
      const size_t avail = pad_size - m_pad_pos;
      const size_t take = std::min(length, avail);
      xor_buf(out, in, pad_bits + m_pad_pos, take);
      length -= take;
      in += take;
      out += take;
      m_pad_pos += take;

      if(take == avail)
         {
         add_counter(m_ctr_blocks);
         m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
         m_pad_pos = 0;
         }
      }

   while(length >= pad_size)
      {
      xor_buf(out, in, pad_bits, pad_size);
      length -= pad_size;
      in += pad_size;
      out += pad_size;

      add_counter(m_ctr_blocks);
      m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
      }

   xor_buf(out, in, pad_bits, length);
   m_pad_pos += length;
   }

void CTR_BE::set_iv(const uint8_t iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   m_iv.resize(m_block_size);
   zeroise(m_iv);
   buffer_insert(m_iv, 0, iv, iv_len);

   seek(0);
   }

void CTR_BE::add_counter(const uint64_t counter)
   {
   const size_t ctr_size = m_ctr_size;
   const size_t ctr_blocks = m_ctr_blocks;
   const size_t BS = m_block_size;

   if(ctr_size == 4)
      {
      const size_t off = (BS - 4);
      const uint32_t low32 = static_cast<uint32_t>(counter + load_be<uint32_t>(&m_counter[off], 0));

      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         store_be(uint32_t(low32 + i), &m_counter[i*BS+off]);
         }
      }
   else if(ctr_size == 8)
      {
      const size_t off = (BS - 8);
      const uint64_t low64 = counter + load_be<uint64_t>(&m_counter[off], 0);

      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         store_be(uint64_t(low64 + i), &m_counter[i*BS+off]);
         }
      }
   else if(ctr_size == 16)
      {
      const size_t off = (BS - 16);
      uint64_t b0 = load_be<uint64_t>(&m_counter[off], 0);
      uint64_t b1 = load_be<uint64_t>(&m_counter[off], 1);
      b1 += counter;
      b0 += (b1 < counter) ? 1 : 0; // carry

      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         store_be(b0, &m_counter[i*BS+off]);
         store_be(b1, &m_counter[i*BS+off+8]);
         b1 += 1;
         b0 += (b1 == 0); // carry
         }
      }
   else
      {
      for(size_t i = 0; i != ctr_blocks; ++i)
         {
         uint64_t local_counter = counter;
         uint16_t carry = static_cast<uint8_t>(local_counter);
         for(size_t j = 0; (carry || local_counter) && j != ctr_size; ++j)
            {
            const size_t off = i*BS + (BS-1-j);
            const uint16_t cnt = static_cast<uint16_t>(m_counter[off]) + carry;
            m_counter[off] = static_cast<uint8_t>(cnt);
            local_counter = (local_counter >> 8);
            carry = (cnt >> 8) + static_cast<uint8_t>(local_counter);
            }
         }
      }
   }

void CTR_BE::seek(uint64_t offset)
   {
   verify_key_set(m_iv.empty() == false);

   const uint64_t base_counter = m_ctr_blocks * (offset / m_counter.size());

   zeroise(m_counter);
   buffer_insert(m_counter, 0, m_iv);

   const size_t BS = m_block_size;

   // Set m_counter blocks to IV, IV + 1, ... IV + n

   if(m_ctr_size == 4 && BS >= 8)
      {
      const uint32_t low32 = load_be<uint32_t>(&m_counter[BS-4], 0);

      if(m_ctr_blocks >= 4 && is_power_of_2(m_ctr_blocks))
         {
         size_t written = 1;
         while(written < m_ctr_blocks)
            {
            copy_mem(&m_counter[written*BS], &m_counter[0], BS*written);
            written *= 2;
            }
         }
      else
         {
         for(size_t i = 1; i != m_ctr_blocks; ++i)
            {
            copy_mem(&m_counter[i*BS], &m_counter[0], BS - 4);
            }
         }

      for(size_t i = 1; i != m_ctr_blocks; ++i)
         {
         const uint32_t c = static_cast<uint32_t>(low32 + i);
         store_be(c, &m_counter[(BS-4)+i*BS]);
         }
      }
   else
      {
      // do everything sequentially:
      for(size_t i = 1; i != m_ctr_blocks; ++i)
         {
         buffer_insert(m_counter, i*BS, &m_counter[(i-1)*BS], BS);

         for(size_t j = 0; j != m_ctr_size; ++j)
            if(++m_counter[i*BS + (BS - 1 - j)])
               break;
         }
      }

   if(base_counter > 0)
      add_counter(base_counter);

   m_cipher->encrypt_n(m_counter.data(), m_pad.data(), m_ctr_blocks);
   m_pad_pos = offset % m_counter.size();
   }
}
/*
* Entropy Source Polling
* (C) 2008-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_SYSTEM_RNG)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DARN)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
#endif

namespace Botan {

#if defined(BOTAN_HAS_SYSTEM_RNG)

namespace {

class System_RNG_EntropySource final : public Entropy_Source
   {
   public:
      size_t poll(RandomNumberGenerator& rng) override
         {
         const size_t poll_bits = BOTAN_RNG_RESEED_POLL_BITS;
         rng.reseed_from_rng(system_rng(), poll_bits);
         return poll_bits;
         }

      std::string name() const override { return "system_rng"; }
   };

}

#endif

std::unique_ptr<Entropy_Source> Entropy_Source::create(const std::string& name)
   {
#if defined(BOTAN_HAS_SYSTEM_RNG)
   if(name == "system_rng" || name == "win32_cryptoapi")
      {
      return std::unique_ptr<Entropy_Source>(new System_RNG_EntropySource);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDRAND)
   if(name == "rdrand")
      {
      return std::unique_ptr<Entropy_Source>(new Intel_Rdrand);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_RDSEED)
   if(name == "rdseed")
      {
      return std::unique_ptr<Entropy_Source>(new Intel_Rdseed);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DARN)
   if(name == "p9_darn")
      {
      return std::unique_ptr<Entropy_Source>(new POWER9_DARN);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_GETENTROPY)
   if(name == "getentropy")
      {
      return std::unique_ptr<Entropy_Source>(new Getentropy);
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM)
   if(name == "dev_random")
      {
      return std::unique_ptr<Entropy_Source>(new Device_EntropySource(BOTAN_SYSTEM_RNG_POLL_DEVICES));
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_PROC_WALKER)
   if(name == "proc_walk" && OS::running_in_privileged_state() == false)
      {
      const std::string root_dir = BOTAN_ENTROPY_PROC_FS_PATH;
      if(!root_dir.empty())
         return std::unique_ptr<Entropy_Source>(new ProcWalking_EntropySource(root_dir));
      }
#endif

#if defined(BOTAN_HAS_ENTROPY_SRC_WIN32)
   if(name == "system_stats")
      {
      return std::unique_ptr<Entropy_Source>(new Win32_EntropySource);
      }
#endif

   BOTAN_UNUSED(name);
   return std::unique_ptr<Entropy_Source>();
   }

void Entropy_Sources::add_source(std::unique_ptr<Entropy_Source> src)
   {
   if(src.get())
      {
      m_srcs.push_back(std::move(src));
      }
   }

std::vector<std::string> Entropy_Sources::enabled_sources() const
   {
   std::vector<std::string> sources;
   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      sources.push_back(m_srcs[i]->name());
      }
   return sources;
   }

size_t Entropy_Sources::poll(RandomNumberGenerator& rng,
                             size_t poll_bits,
                             std::chrono::milliseconds timeout)
   {
   typedef std::chrono::system_clock clock;

   auto deadline = clock::now() + timeout;

   size_t bits_collected = 0;

   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      bits_collected += m_srcs[i]->poll(rng);

      if (bits_collected >= poll_bits || clock::now() > deadline)
         break;
      }

   return bits_collected;
   }

size_t Entropy_Sources::poll_just(RandomNumberGenerator& rng, const std::string& the_src)
   {
   for(size_t i = 0; i != m_srcs.size(); ++i)
      {
      if(m_srcs[i]->name() == the_src)
         {
         return m_srcs[i]->poll(rng);
         }
      }

   return 0;
   }

Entropy_Sources::Entropy_Sources(const std::vector<std::string>& sources)
   {
   for(auto&& src_name : sources)
      {
      add_source(Entropy_Source::create(src_name));
      }
   }

Entropy_Sources& Entropy_Sources::global_sources()
   {
   static Entropy_Sources global_entropy_sources(BOTAN_ENTROPY_DEFAULT_SOURCES);

   return global_entropy_sources;
   }

}

/*
* Filters
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

#if defined(BOTAN_HAS_STREAM_CIPHER)

StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher) :
   m_buffer(BOTAN_DEFAULT_BUFFER_SIZE),
   m_cipher(cipher)
   {
   }

StreamCipher_Filter::StreamCipher_Filter(StreamCipher* cipher, const SymmetricKey& key) :
   StreamCipher_Filter(cipher)
   {
   m_cipher->set_key(key);
   }

StreamCipher_Filter::StreamCipher_Filter(const std::string& sc_name) :
   m_buffer(BOTAN_DEFAULT_BUFFER_SIZE),
   m_cipher(StreamCipher::create_or_throw(sc_name))
   {
   }

StreamCipher_Filter::StreamCipher_Filter(const std::string& sc_name, const SymmetricKey& key) :
   StreamCipher_Filter(sc_name)
   {
   m_cipher->set_key(key);
   }

void StreamCipher_Filter::write(const uint8_t input[], size_t length)
   {
   while(length)
      {
      size_t copied = std::min<size_t>(length, m_buffer.size());
      m_cipher->cipher(input, m_buffer.data(), copied);
      send(m_buffer, copied);
      input += copied;
      length -= copied;
      }
   }

#endif

#if defined(BOTAN_HAS_HASH)

Hash_Filter::Hash_Filter(const std::string& hash_name, size_t len) :
   m_hash(HashFunction::create_or_throw(hash_name)),
   m_out_len(len)
   {
   }

void Hash_Filter::end_msg()
   {
   secure_vector<uint8_t> output = m_hash->final();
   if(m_out_len)
      send(output, std::min<size_t>(m_out_len, output.size()));
   else
      send(output);
   }
#endif

#if defined(BOTAN_HAS_MAC)

MAC_Filter::MAC_Filter(const std::string& mac_name, size_t len) :
   m_mac(MessageAuthenticationCode::create_or_throw(mac_name)),
   m_out_len(len)
   {
   }

MAC_Filter::MAC_Filter(const std::string& mac_name, const SymmetricKey& key, size_t len) :
   MAC_Filter(mac_name, len)
   {
   m_mac->set_key(key);
   }

void MAC_Filter::end_msg()
   {
   secure_vector<uint8_t> output = m_mac->final();
   if(m_out_len)
      send(output, std::min<size_t>(m_out_len, output.size()));
   else
      send(output);
   }

#endif

}
/*
* Base64 Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Base64_Encoder Constructor
*/
Base64_Encoder::Base64_Encoder(bool breaks, size_t length, bool t_n) :
   m_line_length(breaks ? length : 0),
   m_trailing_newline(t_n && breaks),
   m_in(48),
   m_out(64),
   m_position(0),
   m_out_position(0)
   {
   }

/*
* Encode and send a block
*/
void Base64_Encoder::encode_and_send(const uint8_t input[], size_t length,
                                     bool final_inputs)
   {
   while(length)
      {
      const size_t proc = std::min(length, m_in.size());

      size_t consumed = 0;
      size_t produced = base64_encode(cast_uint8_ptr_to_char(m_out.data()),
                                      input, proc, consumed, final_inputs);

      do_output(m_out.data(), produced);

      // FIXME: s/proc/consumed/?
      input += proc;
      length -= proc;
      }
   }

/*
* Handle the output
*/
void Base64_Encoder::do_output(const uint8_t input[], size_t length)
   {
   if(m_line_length == 0)
      send(input, length);
   else
      {
      size_t remaining = length, offset = 0;
      while(remaining)
         {
         size_t sent = std::min(m_line_length - m_out_position, remaining);
         send(input + offset, sent);
         m_out_position += sent;
         remaining -= sent;
         offset += sent;
         if(m_out_position == m_line_length)
            {
            send('\n');
            m_out_position = 0;
            }
         }
      }
   }

/*
* Convert some data into Base64
*/
void Base64_Encoder::write(const uint8_t input[], size_t length)
   {
   buffer_insert(m_in, m_position, input, length);
   if(m_position + length >= m_in.size())
      {
      encode_and_send(m_in.data(), m_in.size());
      input += (m_in.size() - m_position);
      length -= (m_in.size() - m_position);
      while(length >= m_in.size())
         {
         encode_and_send(input, m_in.size());
         input += m_in.size();
         length -= m_in.size();
         }
      copy_mem(m_in.data(), input, length);
      m_position = 0;
      }
   m_position += length;
   }

/*
* Flush buffers
*/
void Base64_Encoder::end_msg()
   {
   encode_and_send(m_in.data(), m_position, true);

   if(m_trailing_newline || (m_out_position && m_line_length))
      send('\n');

   m_out_position = m_position = 0;
   }

/*
* Base64_Decoder Constructor
*/
Base64_Decoder::Base64_Decoder(Decoder_Checking c) :
   m_checking(c), m_in(64), m_out(48), m_position(0)
   {
   }

/*
* Convert some data from Base64
*/
void Base64_Decoder::write(const uint8_t input[], size_t length)
   {
   while(length)
      {
      size_t to_copy = std::min<size_t>(length, m_in.size() - m_position);
      if(to_copy == 0)
         {
         m_in.resize(m_in.size()*2);
         m_out.resize(m_out.size()*2);
         }
      copy_mem(&m_in[m_position], input, to_copy);
      m_position += to_copy;

      size_t consumed = 0;
      size_t written = base64_decode(m_out.data(),
                                     cast_uint8_ptr_to_char(m_in.data()),
                                     m_position,
                                     consumed,
                                     false,
                                     m_checking != FULL_CHECK);

      send(m_out, written);

      if(consumed != m_position)
         {
         copy_mem(m_in.data(), m_in.data() + consumed, m_position - consumed);
         m_position = m_position - consumed;
         }
      else
         m_position = 0;

      length -= to_copy;
      input += to_copy;
      }
   }

/*
* Flush buffers
*/
void Base64_Decoder::end_msg()
   {
   size_t consumed = 0;
   size_t written = base64_decode(m_out.data(),
                                  cast_uint8_ptr_to_char(m_in.data()),
                                  m_position,
                                  consumed,
                                  true,
                                  m_checking != FULL_CHECK);

   send(m_out, written);

   const bool not_full_bytes = consumed != m_position;

   m_position = 0;

   if(not_full_bytes)
      throw Invalid_Argument("Base64_Decoder: Input not full bytes");
   }

}
/*
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Chain Constructor
*/
Chain::Chain(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
   {
   if(f1) { attach(f1); incr_owns(); }
   if(f2) { attach(f2); incr_owns(); }
   if(f3) { attach(f3); incr_owns(); }
   if(f4) { attach(f4); incr_owns(); }
   }

/*
* Chain Constructor
*/
Chain::Chain(Filter* filters[], size_t count)
   {
   for(size_t j = 0; j != count; ++j)
      if(filters[j])
         {
         attach(filters[j]);
         incr_owns();
         }
   }

/*
* Fork Constructor
*/
Fork::Fork(Filter* f1, Filter* f2, Filter* f3, Filter* f4)
   {
   Filter* filters[4] = { f1, f2, f3, f4 };
   set_next(filters, 4);
   }

/*
* Fork Constructor
*/
Fork::Fork(Filter* filters[], size_t count)
   {
   set_next(filters, count);
   }

}
/*
* Buffered Filter
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Buffered_Filter Constructor
*/
Buffered_Filter::Buffered_Filter(size_t b, size_t f) :
   m_main_block_mod(b), m_final_minimum(f)
   {
   if(m_main_block_mod == 0)
      throw Invalid_Argument("m_main_block_mod == 0");

   if(m_final_minimum > m_main_block_mod)
      throw Invalid_Argument("m_final_minimum > m_main_block_mod");

   m_buffer.resize(2 * m_main_block_mod);
   m_buffer_pos = 0;
   }

/*
* Buffer input into blocks, trying to minimize copying
*/
void Buffered_Filter::write(const uint8_t input[], size_t input_size)
   {
   if(!input_size)
      return;

   if(m_buffer_pos + input_size >= m_main_block_mod + m_final_minimum)
      {
      size_t to_copy = std::min<size_t>(m_buffer.size() - m_buffer_pos, input_size);

      copy_mem(&m_buffer[m_buffer_pos], input, to_copy);
      m_buffer_pos += to_copy;

      input += to_copy;
      input_size -= to_copy;

      size_t total_to_consume =
         round_down(std::min(m_buffer_pos,
                             m_buffer_pos + input_size - m_final_minimum),
                    m_main_block_mod);

      buffered_block(m_buffer.data(), total_to_consume);

      m_buffer_pos -= total_to_consume;

      copy_mem(m_buffer.data(), m_buffer.data() + total_to_consume, m_buffer_pos);
      }

   if(input_size >= m_final_minimum)
      {
      size_t full_blocks = (input_size - m_final_minimum) / m_main_block_mod;
      size_t to_copy = full_blocks * m_main_block_mod;

      if(to_copy)
         {
         buffered_block(input, to_copy);

         input += to_copy;
         input_size -= to_copy;
         }
      }

   copy_mem(&m_buffer[m_buffer_pos], input, input_size);
   m_buffer_pos += input_size;
   }

/*
* Finish/flush operation
*/
void Buffered_Filter::end_msg()
   {
   if(m_buffer_pos < m_final_minimum)
      throw Invalid_State("Buffered filter end_msg without enough input");

   size_t spare_blocks = (m_buffer_pos - m_final_minimum) / m_main_block_mod;

   if(spare_blocks)
      {
      size_t spare_bytes = m_main_block_mod * spare_blocks;
      buffered_block(m_buffer.data(), spare_bytes);
      buffered_final(&m_buffer[spare_bytes], m_buffer_pos - spare_bytes);
      }
   else
      {
      buffered_final(m_buffer.data(), m_buffer_pos);
      }

   m_buffer_pos = 0;
   }

}
/*
* Filter interface for Cipher_Modes
* (C) 2013,2014,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

size_t choose_update_size(size_t update_granularity)
   {
   const size_t target_size = 1024;

   if(update_granularity >= target_size)
      return update_granularity;

   return round_up(target_size, update_granularity);
   }

}

Cipher_Mode_Filter::Cipher_Mode_Filter(Cipher_Mode* mode) :
   Buffered_Filter(choose_update_size(mode->update_granularity()),
                   mode->minimum_final_size()),
   m_mode(mode),
   m_nonce(mode->default_nonce_length()),
   m_buffer(m_mode->update_granularity())
   {
   }

std::string Cipher_Mode_Filter::name() const
   {
   return m_mode->name();
   }

void Cipher_Mode_Filter::set_iv(const InitializationVector& iv)
   {
   m_nonce = unlock(iv.bits_of());
   }

void Cipher_Mode_Filter::set_key(const SymmetricKey& key)
   {
   m_mode->set_key(key);
   }

Key_Length_Specification Cipher_Mode_Filter::key_spec() const
   {
   return m_mode->key_spec();
   }

bool Cipher_Mode_Filter::valid_iv_length(size_t length) const
   {
   return m_mode->valid_nonce_length(length);
   }

void Cipher_Mode_Filter::write(const uint8_t input[], size_t input_length)
   {
   Buffered_Filter::write(input, input_length);
   }

void Cipher_Mode_Filter::end_msg()
   {
   Buffered_Filter::end_msg();
   }

void Cipher_Mode_Filter::start_msg()
   {
   if(m_nonce.empty() && !m_mode->valid_nonce_length(0))
      throw Invalid_State("Cipher " + m_mode->name() + " requires a fresh nonce for each message");

   m_mode->start(m_nonce);
   m_nonce.clear();
   }

void Cipher_Mode_Filter::buffered_block(const uint8_t input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min(m_mode->update_granularity(), input_length);

      m_buffer.assign(input, input + take);
      m_mode->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Cipher_Mode_Filter::buffered_final(const uint8_t input[], size_t input_length)
   {
   secure_vector<uint8_t> buf(input, input + input_length);
   m_mode->finish(buf);
   send(buf);
   }

}
/*
* Filter interface for compression
* (C) 2014,2015,2016 Jack Lloyd
* (C) 2015 Matej Kenda
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_COMPRESSION)
#endif

namespace Botan {

#if defined(BOTAN_HAS_COMPRESSION)

Compression_Filter::Compression_Filter(const std::string& type, size_t level, size_t bs) :
   m_comp(make_compressor(type)),
   m_buffersize(std::max<size_t>(bs, 256)),
   m_level(level)
   {
   if(!m_comp)
      {
      throw Invalid_Argument("Compression type '" + type + "' not found");
      }
   }

Compression_Filter::~Compression_Filter() { /* for unique_ptr */ }

std::string Compression_Filter::name() const
   {
   return m_comp->name();
   }

void Compression_Filter::start_msg()
   {
   m_comp->start(m_level);
   }

void Compression_Filter::write(const uint8_t input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min(m_buffersize, input_length);
      BOTAN_ASSERT(take > 0, "Consumed something");

      m_buffer.assign(input, input + take);
      m_comp->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Compression_Filter::flush()
   {
   m_buffer.clear();
   m_comp->update(m_buffer, 0, true);
   send(m_buffer);
   }

void Compression_Filter::end_msg()
   {
   m_buffer.clear();
   m_comp->finish(m_buffer);
   send(m_buffer);
   }

Decompression_Filter::Decompression_Filter(const std::string& type, size_t bs) :
   m_comp(make_decompressor(type)),
   m_buffersize(std::max<size_t>(bs, 256))
   {
   if(!m_comp)
      {
      throw Invalid_Argument("Compression type '" + type + "' not found");
      }
   }

Decompression_Filter::~Decompression_Filter() { /* for unique_ptr */ }

std::string Decompression_Filter::name() const
   {
   return m_comp->name();
   }

void Decompression_Filter::start_msg()
   {
   m_comp->start();
   }

void Decompression_Filter::write(const uint8_t input[], size_t input_length)
   {
   while(input_length)
      {
      const size_t take = std::min(m_buffersize, input_length);
      BOTAN_ASSERT(take > 0, "Consumed something");

      m_buffer.assign(input, input + take);
      m_comp->update(m_buffer);

      send(m_buffer);

      input += take;
      input_length -= take;
      }
   }

void Decompression_Filter::end_msg()
   {
   m_buffer.clear();
   m_comp->finish(m_buffer);
   send(m_buffer);
   }

#endif

}
/*
* DataSink
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*     2017 Philippe Lieser
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
  #include <fstream>
#endif

namespace Botan {

/*
* Write to a stream
*/
void DataSink_Stream::write(const uint8_t out[], size_t length)
   {
   m_sink.write(cast_uint8_ptr_to_char(out), length);
   if(!m_sink.good())
      throw Stream_IO_Error("DataSink_Stream: Failure writing to " +
                            m_identifier);
   }

/*
* Flush the stream
*/
void DataSink_Stream::end_msg()
   {
   m_sink.flush();
   }

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(std::ostream& out,
                                 const std::string& name) :
   m_identifier(name),
   m_sink(out)
   {
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

/*
* DataSink_Stream Constructor
*/
DataSink_Stream::DataSink_Stream(const std::string& path,
                                 bool use_binary) :
   m_identifier(path),
   m_sink_memory(new std::ofstream(path, use_binary ? std::ios::binary : std::ios::out)),
   m_sink(*m_sink_memory)
   {
   if(!m_sink.good())
      {
      throw Stream_IO_Error("DataSink_Stream: Failure opening " + path);
      }
   }
#endif

/*
* DataSink_Stream Destructor
*/
DataSink_Stream::~DataSink_Stream()
   {
   // for ~unique_ptr
   }

}
/*
* Filter
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Filter Constructor
*/
Filter::Filter()
   {
   m_next.resize(1);
   m_port_num = 0;
   m_filter_owns = 0;
   m_owned = false;
   }

/*
* Send data to all ports
*/
void Filter::send(const uint8_t input[], size_t length)
   {
   if(!length)
      return;

   bool nothing_attached = true;
   for(size_t j = 0; j != total_ports(); ++j)
      if(m_next[j])
         {
         if(m_write_queue.size())
            m_next[j]->write(m_write_queue.data(), m_write_queue.size());
         m_next[j]->write(input, length);
         nothing_attached = false;
         }

   if(nothing_attached)
      m_write_queue += std::make_pair(input, length);
   else
      m_write_queue.clear();
   }

/*
* Start a new message
*/
void Filter::new_msg()
   {
   start_msg();
   for(size_t j = 0; j != total_ports(); ++j)
      if(m_next[j])
         m_next[j]->new_msg();
   }

/*
* End the current message
*/
void Filter::finish_msg()
   {
   end_msg();
   for(size_t j = 0; j != total_ports(); ++j)
      if(m_next[j])
         m_next[j]->finish_msg();
   }

/*
* Attach a filter to the current port
*/
void Filter::attach(Filter* new_filter)
   {
   if(new_filter)
      {
      Filter* last = this;
      while(last->get_next())
         last = last->get_next();
      last->m_next[last->current_port()] = new_filter;
      }
   }

/*
* Set the active port on a filter
*/
void Filter::set_port(size_t new_port)
   {
   if(new_port >= total_ports())
      throw Invalid_Argument("Filter: Invalid port number");
   m_port_num = new_port;
   }

/*
* Return the next Filter in the logical chain
*/
Filter* Filter::get_next() const
   {
   if(m_port_num < m_next.size())
      return m_next[m_port_num];
   return nullptr;
   }

/*
* Set the next Filters
*/
void Filter::set_next(Filter* filters[], size_t size)
   {
   m_next.clear();

   m_port_num = 0;
   m_filter_owns = 0;

   while(size && filters && (filters[size-1] == nullptr))
      --size;

   if(filters && size)
      m_next.assign(filters, filters + size);
   }

/*
* Return the total number of ports
*/
size_t Filter::total_ports() const
   {
   return m_next.size();
   }

}
/*
* Hex Encoder/Decoder
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/**
* Size used for internal buffer in hex encoder/decoder
*/
const size_t HEX_CODEC_BUFFER_SIZE = 256;

/*
* Hex_Encoder Constructor
*/
Hex_Encoder::Hex_Encoder(bool breaks, size_t length, Case c) :
   m_casing(c), m_line_length(breaks ? length : 0)
   {
   m_in.resize(HEX_CODEC_BUFFER_SIZE);
   m_out.resize(2*m_in.size());
   m_counter = m_position = 0;
   }

/*
* Hex_Encoder Constructor
*/
Hex_Encoder::Hex_Encoder(Case c) : m_casing(c), m_line_length(0)
   {
   m_in.resize(HEX_CODEC_BUFFER_SIZE);
   m_out.resize(2*m_in.size());
   m_counter = m_position = 0;
   }

/*
* Encode and send a block
*/
void Hex_Encoder::encode_and_send(const uint8_t block[], size_t length)
   {
   hex_encode(cast_uint8_ptr_to_char(m_out.data()),
              block, length,
              m_casing == Uppercase);

   if(m_line_length == 0)
      send(m_out, 2*length);
   else
      {
      size_t remaining = 2*length, offset = 0;
      while(remaining)
         {
         size_t sent = std::min(m_line_length - m_counter, remaining);
         send(&m_out[offset], sent);
         m_counter += sent;
         remaining -= sent;
         offset += sent;
         if(m_counter == m_line_length)
            {
            send('\n');
            m_counter = 0;
            }
         }
      }
   }

/*
* Convert some data into hex format
*/
void Hex_Encoder::write(const uint8_t input[], size_t length)
   {
   buffer_insert(m_in, m_position, input, length);
   if(m_position + length >= m_in.size())
      {
      encode_and_send(m_in.data(), m_in.size());
      input += (m_in.size() - m_position);
      length -= (m_in.size() - m_position);
      while(length >= m_in.size())
         {
         encode_and_send(input, m_in.size());
         input += m_in.size();
         length -= m_in.size();
         }
      copy_mem(m_in.data(), input, length);
      m_position = 0;
      }
   m_position += length;
   }

/*
* Flush buffers
*/
void Hex_Encoder::end_msg()
   {
   encode_and_send(m_in.data(), m_position);
   if(m_counter && m_line_length)
      send('\n');
   m_counter = m_position = 0;
   }

/*
* Hex_Decoder Constructor
*/
Hex_Decoder::Hex_Decoder(Decoder_Checking c) : m_checking(c)
   {
   m_in.resize(HEX_CODEC_BUFFER_SIZE);
   m_out.resize(m_in.size() / 2);
   m_position = 0;
   }

/*
* Convert some data from hex format
*/
void Hex_Decoder::write(const uint8_t input[], size_t length)
   {
   while(length)
      {
      size_t to_copy = std::min<size_t>(length, m_in.size() - m_position);
      copy_mem(&m_in[m_position], input, to_copy);
      m_position += to_copy;

      size_t consumed = 0;
      size_t written = hex_decode(m_out.data(),
                                  cast_uint8_ptr_to_char(m_in.data()),
                                  m_position,
                                  consumed,
                                  m_checking != FULL_CHECK);

      send(m_out, written);

      if(consumed != m_position)
         {
         copy_mem(m_in.data(), m_in.data() + consumed, m_position - consumed);
         m_position = m_position - consumed;
         }
      else
         m_position = 0;

      length -= to_copy;
      input += to_copy;
      }
   }

/*
* Flush buffers
*/
void Hex_Decoder::end_msg()
   {
   size_t consumed = 0;
   size_t written = hex_decode(m_out.data(),
                               cast_uint8_ptr_to_char(m_in.data()),
                               m_position,
                               consumed,
                               m_checking != FULL_CHECK);

   send(m_out, written);

   const bool not_full_bytes = consumed != m_position;

   m_position = 0;

   if(not_full_bytes)
      throw Invalid_Argument("Hex_Decoder: Input not full bytes");
   }

}
/*
* Pipe Output Buffer
* (C) 1999-2007,2011 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Read data from a message
*/
size_t Output_Buffers::read(uint8_t output[], size_t length,
                            Pipe::message_id msg)
   {
   SecureQueue* q = get(msg);
   if(q)
      return q->read(output, length);
   return 0;
   }

/*
* Peek at data in a message
*/
size_t Output_Buffers::peek(uint8_t output[], size_t length,
                            size_t stream_offset,
                            Pipe::message_id msg) const
   {
   SecureQueue* q = get(msg);
   if(q)
      return q->peek(output, length, stream_offset);
   return 0;
   }

/*
* Check available bytes in a message
*/
size_t Output_Buffers::remaining(Pipe::message_id msg) const
   {
   SecureQueue* q = get(msg);
   if(q)
      return q->size();
   return 0;
   }

/*
* Return the total bytes of a message that have already been read.
*/
size_t Output_Buffers::get_bytes_read(Pipe::message_id msg) const
   {
   SecureQueue* q = get(msg);
   if (q)
      return q->get_bytes_read();
   return 0;
   }

/*
* Add a new output queue
*/
void Output_Buffers::add(SecureQueue* queue)
   {
   BOTAN_ASSERT(queue, "queue was provided");

   BOTAN_ASSERT(m_buffers.size() < m_buffers.max_size(),
                "Room was available in container");

   m_buffers.push_back(std::unique_ptr<SecureQueue>(queue));
   }

/*
* Retire old output queues
*/
void Output_Buffers::retire()
   {
   for(size_t i = 0; i != m_buffers.size(); ++i)
      if(m_buffers[i] && m_buffers[i]->size() == 0)
         {
         m_buffers[i].reset();
         }

   while(m_buffers.size() && !m_buffers[0])
      {
      m_buffers.pop_front();
      m_offset = m_offset + Pipe::message_id(1);
      }
   }

/*
* Get a particular output queue
*/
SecureQueue* Output_Buffers::get(Pipe::message_id msg) const
   {
   if(msg < m_offset)
      return nullptr;

   BOTAN_ASSERT(msg < message_count(), "Message number is in range");

   return m_buffers[msg-m_offset].get();
   }

/*
* Return the total number of messages
*/
Pipe::message_id Output_Buffers::message_count() const
   {
   return (m_offset + m_buffers.size());
   }

/*
* Output_Buffers Constructor
*/
Output_Buffers::Output_Buffers()
   {
   m_offset = 0;
   }

}
/*
* Pipe
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* A Filter that does nothing
*/
class Null_Filter final : public Filter
   {
   public:
      void write(const uint8_t input[], size_t length) override
         { send(input, length); }

      std::string name() const override { return "Null"; }
   };

}

/*
* Pipe Constructor
*/
Pipe::Pipe(Filter* f1, Filter* f2, Filter* f3, Filter* f4) :
   Pipe({f1,f2,f3,f4})
   {
   }

/*
* Pipe Constructor
*/
Pipe::Pipe(std::initializer_list<Filter*> args)
   {
   m_outputs.reset(new Output_Buffers);
   m_pipe = nullptr;
   m_default_read = 0;
   m_inside_msg = false;

   for(auto i = args.begin(); i != args.end(); ++i)
      do_append(*i);
   }

/*
* Pipe Destructor
*/
Pipe::~Pipe()
   {
   destruct(m_pipe);
   }

/*
* Reset the Pipe
*/
void Pipe::reset()
   {
   destruct(m_pipe);
   m_pipe = nullptr;
   m_inside_msg = false;
   }

/*
* Destroy the Pipe
*/
void Pipe::destruct(Filter* to_kill)
   {
   if(!to_kill || dynamic_cast<SecureQueue*>(to_kill))
      return;
   for(size_t j = 0; j != to_kill->total_ports(); ++j)
      destruct(to_kill->m_next[j]);
   delete to_kill;
   }

/*
* Test if the Pipe has any data in it
*/
bool Pipe::end_of_data() const
   {
   return (remaining() == 0);
   }

/*
* Set the default read message
*/
void Pipe::set_default_msg(message_id msg)
   {
   if(msg >= message_count())
      throw Invalid_Argument("Pipe::set_default_msg: msg number is too high");
   m_default_read = msg;
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(const uint8_t input[], size_t length)
   {
   start_msg();
   write(input, length);
   end_msg();
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(const secure_vector<uint8_t>& input)
   {
   process_msg(input.data(), input.size());
   }

void Pipe::process_msg(const std::vector<uint8_t>& input)
   {
   process_msg(input.data(), input.size());
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(const std::string& input)
   {
   process_msg(cast_char_ptr_to_uint8(input.data()), input.length());
   }

/*
* Process a full message at once
*/
void Pipe::process_msg(DataSource& input)
   {
   start_msg();
   write(input);
   end_msg();
   }

/*
* Start a new message
*/
void Pipe::start_msg()
   {
   if(m_inside_msg)
      throw Invalid_State("Pipe::start_msg: Message was already started");
   if(m_pipe == nullptr)
      m_pipe = new Null_Filter;
   find_endpoints(m_pipe);
   m_pipe->new_msg();
   m_inside_msg = true;
   }

/*
* End the current message
*/
void Pipe::end_msg()
   {
   if(!m_inside_msg)
      throw Invalid_State("Pipe::end_msg: Message was already ended");
   m_pipe->finish_msg();
   clear_endpoints(m_pipe);
   if(dynamic_cast<Null_Filter*>(m_pipe))
      {
      delete m_pipe;
      m_pipe = nullptr;
      }
   m_inside_msg = false;

   m_outputs->retire();
   }

/*
* Find the endpoints of the Pipe
*/
void Pipe::find_endpoints(Filter* f)
   {
   for(size_t j = 0; j != f->total_ports(); ++j)
      if(f->m_next[j] && !dynamic_cast<SecureQueue*>(f->m_next[j]))
         find_endpoints(f->m_next[j]);
      else
         {
         SecureQueue* q = new SecureQueue;
         f->m_next[j] = q;
         m_outputs->add(q);
         }
   }

/*
* Remove the SecureQueues attached to the Filter
*/
void Pipe::clear_endpoints(Filter* f)
   {
   if(!f) return;
   for(size_t j = 0; j != f->total_ports(); ++j)
      {
      if(f->m_next[j] && dynamic_cast<SecureQueue*>(f->m_next[j]))
         f->m_next[j] = nullptr;
      clear_endpoints(f->m_next[j]);
      }
   }

void Pipe::append(Filter* filter)
   {
   do_append(filter);
   }

void Pipe::append_filter(Filter* filter)
   {
   if(m_outputs->message_count() != 0)
      throw Invalid_State("Cannot call Pipe::append_filter after start_msg");

   do_append(filter);
   }

void Pipe::prepend(Filter* filter)
   {
   do_prepend(filter);
   }

void Pipe::prepend_filter(Filter* filter)
   {
   if(m_outputs->message_count() != 0)
      throw Invalid_State("Cannot call Pipe::prepend_filter after start_msg");

   do_prepend(filter);
   }

/*
* Append a Filter to the Pipe
*/
void Pipe::do_append(Filter* filter)
   {
   if(!filter)
      return;
   if(dynamic_cast<SecureQueue*>(filter))
      throw Invalid_Argument("Pipe::append: SecureQueue cannot be used");
   if(filter->m_owned)
      throw Invalid_Argument("Filters cannot be shared among multiple Pipes");

   if(m_inside_msg)
      throw Invalid_State("Cannot append to a Pipe while it is processing");

   filter->m_owned = true;

   if(!m_pipe) m_pipe = filter;
   else      m_pipe->attach(filter);
   }

/*
* Prepend a Filter to the Pipe
*/
void Pipe::do_prepend(Filter* filter)
   {
   if(m_inside_msg)
      throw Invalid_State("Cannot prepend to a Pipe while it is processing");
   if(!filter)
      return;
   if(dynamic_cast<SecureQueue*>(filter))
      throw Invalid_Argument("Pipe::prepend: SecureQueue cannot be used");
   if(filter->m_owned)
      throw Invalid_Argument("Filters cannot be shared among multiple Pipes");

   filter->m_owned = true;

   if(m_pipe) filter->attach(m_pipe);
   m_pipe = filter;
   }

/*
* Pop a Filter off the Pipe
*/
void Pipe::pop()
   {
   if(m_inside_msg)
      throw Invalid_State("Cannot pop off a Pipe while it is processing");

   if(!m_pipe)
      return;

   if(m_pipe->total_ports() > 1)
      throw Invalid_State("Cannot pop off a Filter with multiple ports");

   size_t to_remove = m_pipe->owns() + 1;

   while(to_remove--)
      {
      std::unique_ptr<Filter> to_destroy(m_pipe);
      m_pipe = m_pipe->m_next[0];
      }
   }

/*
* Return the number of messages in this Pipe
*/
Pipe::message_id Pipe::message_count() const
   {
   return m_outputs->message_count();
   }

/*
* Static Member Variables
*/
const Pipe::message_id Pipe::LAST_MESSAGE =
   static_cast<Pipe::message_id>(-2);

const Pipe::message_id Pipe::DEFAULT_MESSAGE =
   static_cast<Pipe::message_id>(-1);

}
/*
* Pipe I/O
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Write data from a pipe into an ostream
*/
std::ostream& operator<<(std::ostream& stream, Pipe& pipe)
   {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(stream.good() && pipe.remaining())
      {
      const size_t got = pipe.read(buffer.data(), buffer.size());
      stream.write(cast_uint8_ptr_to_char(buffer.data()), got);
      }
   if(!stream.good())
      throw Stream_IO_Error("Pipe output operator (iostream) has failed");
   return stream;
   }

/*
* Read data from an istream into a pipe
*/
std::istream& operator>>(std::istream& stream, Pipe& pipe)
   {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(stream.good())
      {
      stream.read(cast_uint8_ptr_to_char(buffer.data()), buffer.size());
      const size_t got = static_cast<size_t>(stream.gcount());
      pipe.write(buffer.data(), got);
      }
   if(stream.bad() || (stream.fail() && !stream.eof()))
      throw Stream_IO_Error("Pipe input operator (iostream) has failed");
   return stream;
   }

}
/*
* Pipe Reading/Writing
* (C) 1999-2007 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
* Look up the canonical ID for a queue
*/
Pipe::message_id Pipe::get_message_no(const std::string& func_name,
                                      message_id msg) const
   {
   if(msg == DEFAULT_MESSAGE)
      msg = default_msg();
   else if(msg == LAST_MESSAGE)
      msg = message_count() - 1;

   if(msg >= message_count())
      throw Invalid_Message_Number(func_name, msg);

   return msg;
   }

/*
* Write into a Pipe
*/
void Pipe::write(const uint8_t input[], size_t length)
   {
   if(!m_inside_msg)
      throw Invalid_State("Cannot write to a Pipe while it is not processing");
   m_pipe->write(input, length);
   }

/*
* Write a string into a Pipe
*/
void Pipe::write(const std::string& str)
   {
   write(cast_char_ptr_to_uint8(str.data()), str.size());
   }

/*
* Write a single byte into a Pipe
*/
void Pipe::write(uint8_t input)
   {
   write(&input, 1);
   }

/*
* Write the contents of a DataSource into a Pipe
*/
void Pipe::write(DataSource& source)
   {
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   while(!source.end_of_data())
      {
      size_t got = source.read(buffer.data(), buffer.size());
      write(buffer.data(), got);
      }
   }

/*
* Read some data from the pipe
*/
size_t Pipe::read(uint8_t output[], size_t length, message_id msg)
   {
   return m_outputs->read(output, length, get_message_no("read", msg));
   }

/*
* Read some data from the pipe
*/
size_t Pipe::read(uint8_t output[], size_t length)
   {
   return read(output, length, DEFAULT_MESSAGE);
   }

/*
* Read a single byte from the pipe
*/
size_t Pipe::read(uint8_t& out, message_id msg)
   {
   return read(&out, 1, msg);
   }

/*
* Return all data in the pipe
*/
secure_vector<uint8_t> Pipe::read_all(message_id msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   secure_vector<uint8_t> buffer(remaining(msg));
   size_t got = read(buffer.data(), buffer.size(), msg);
   buffer.resize(got);
   return buffer;
   }

/*
* Return all data in the pipe as a string
*/
std::string Pipe::read_all_as_string(message_id msg)
   {
   msg = ((msg != DEFAULT_MESSAGE) ? msg : default_msg());
   secure_vector<uint8_t> buffer(BOTAN_DEFAULT_BUFFER_SIZE);
   std::string str;
   str.reserve(remaining(msg));

   while(true)
      {
      size_t got = read(buffer.data(), buffer.size(), msg);
      if(got == 0)
         break;
      str.append(cast_uint8_ptr_to_char(buffer.data()), got);
      }

   return str;
   }

/*
* Find out how many bytes are ready to read
*/
size_t Pipe::remaining(message_id msg) const
   {
   return m_outputs->remaining(get_message_no("remaining", msg));
   }

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(uint8_t output[], size_t length,
                  size_t offset, message_id msg) const
   {
   return m_outputs->peek(output, length, offset, get_message_no("peek", msg));
   }

/*
* Peek at some data in the pipe
*/
size_t Pipe::peek(uint8_t output[], size_t length, size_t offset) const
   {
   return peek(output, length, offset, DEFAULT_MESSAGE);
   }

/*
* Peek at a byte in the pipe
*/
size_t Pipe::peek(uint8_t& out, size_t offset, message_id msg) const
   {
   return peek(&out, 1, offset, msg);
   }

size_t Pipe::get_bytes_read() const
   {
   return m_outputs->get_bytes_read(default_msg());
   }

size_t Pipe::get_bytes_read(message_id msg) const
   {
   return m_outputs->get_bytes_read(msg);
   }

bool Pipe::check_available(size_t n)
   {
   return (n <= remaining(default_msg()));
   }

bool Pipe::check_available_msg(size_t n, message_id msg)
   {
   return (n <= remaining(msg));
   }

}
/*
* SecureQueue
* (C) 1999-2007 Jack Lloyd
*     2012 Markus Wanner
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/**
* A node in a SecureQueue
*/
class SecureQueueNode final
   {
   public:
      SecureQueueNode() : m_buffer(BOTAN_DEFAULT_BUFFER_SIZE)
         { m_next = nullptr; m_start = m_end = 0; }

      ~SecureQueueNode() { m_next = nullptr; m_start = m_end = 0; }

      size_t write(const uint8_t input[], size_t length)
         {
         size_t copied = std::min<size_t>(length, m_buffer.size() - m_end);
         copy_mem(m_buffer.data() + m_end, input, copied);
         m_end += copied;
         return copied;
         }

      size_t read(uint8_t output[], size_t length)
         {
         size_t copied = std::min(length, m_end - m_start);
         copy_mem(output, m_buffer.data() + m_start, copied);
         m_start += copied;
         return copied;
         }

      size_t peek(uint8_t output[], size_t length, size_t offset = 0)
         {
         const size_t left = m_end - m_start;
         if(offset >= left) return 0;
         size_t copied = std::min(length, left - offset);
         copy_mem(output, m_buffer.data() + m_start + offset, copied);
         return copied;
         }

      size_t size() const { return (m_end - m_start); }
   private:
      friend class SecureQueue;
      SecureQueueNode* m_next;
      secure_vector<uint8_t> m_buffer;
      size_t m_start, m_end;
   };

/*
* Create a SecureQueue
*/
SecureQueue::SecureQueue()
   {
   m_bytes_read = 0;
   set_next(nullptr, 0);
   m_head = m_tail = new SecureQueueNode;
   }

/*
* Copy a SecureQueue
*/
SecureQueue::SecureQueue(const SecureQueue& input) :
   Fanout_Filter(), DataSource()
   {
   m_bytes_read = 0;
   set_next(nullptr, 0);

   m_head = m_tail = new SecureQueueNode;
   SecureQueueNode* temp = input.m_head;
   while(temp)
      {
      write(&temp->m_buffer[temp->m_start], temp->m_end - temp->m_start);
      temp = temp->m_next;
      }
   }

/*
* Destroy this SecureQueue
*/
void SecureQueue::destroy()
   {
   SecureQueueNode* temp = m_head;
   while(temp)
      {
      SecureQueueNode* holder = temp->m_next;
      delete temp;
      temp = holder;
      }
   m_head = m_tail = nullptr;
   }

/*
* Copy a SecureQueue
*/
SecureQueue& SecureQueue::operator=(const SecureQueue& input)
   {
   if(this == &input)
      return *this;

   destroy();
   m_bytes_read = input.get_bytes_read();
   m_head = m_tail = new SecureQueueNode;
   SecureQueueNode* temp = input.m_head;
   while(temp)
      {
      write(&temp->m_buffer[temp->m_start], temp->m_end - temp->m_start);
      temp = temp->m_next;
      }
   return (*this);
   }

/*
* Add some bytes to the queue
*/
void SecureQueue::write(const uint8_t input[], size_t length)
   {
   if(!m_head)
      m_head = m_tail = new SecureQueueNode;
   while(length)
      {
      const size_t n = m_tail->write(input, length);
      input += n;
      length -= n;
      if(length)
         {
         m_tail->m_next = new SecureQueueNode;
         m_tail = m_tail->m_next;
         }
      }
   }

/*
* Read some bytes from the queue
*/
size_t SecureQueue::read(uint8_t output[], size_t length)
   {
   size_t got = 0;
   while(length && m_head)
      {
      const size_t n = m_head->read(output, length);
      output += n;
      got += n;
      length -= n;
      if(m_head->size() == 0)
         {
         SecureQueueNode* holder = m_head->m_next;
         delete m_head;
         m_head = holder;
         }
      }
   m_bytes_read += got;
   return got;
   }

/*
* Read data, but do not remove it from queue
*/
size_t SecureQueue::peek(uint8_t output[], size_t length, size_t offset) const
   {
   SecureQueueNode* current = m_head;

   while(offset && current)
      {
      if(offset >= current->size())
         {
         offset -= current->size();
         current = current->m_next;
         }
      else
         break;
      }

   size_t got = 0;
   while(length && current)
      {
      const size_t n = current->peek(output, length, offset);
      offset = 0;
      output += n;
      got += n;
      length -= n;
      current = current->m_next;
      }
   return got;
   }

/**
* Return how many bytes have been read so far.
*/
size_t SecureQueue::get_bytes_read() const
   {
   return m_bytes_read;
   }

/*
* Return how many bytes the queue holds
*/
size_t SecureQueue::size() const
   {
   SecureQueueNode* current = m_head;
   size_t count = 0;

   while(current)
      {
      count += current->size();
      current = current->m_next;
      }
   return count;
   }

/*
* Test if the queue has any data in it
*/
bool SecureQueue::end_of_data() const
   {
   return (size() == 0);
   }

bool SecureQueue::empty() const
   {
   return (size() == 0);
   }

}
/*
* Threaded Fork
* (C) 2013 Joel Low
*     2013 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_THREAD_UTILS)


namespace Botan {

struct Threaded_Fork_Data
   {
   /*
   * Semaphore for indicating that there is work to be done (or to
   * quit)
   */
   Semaphore m_input_ready_semaphore;

   /*
   * Synchronises all threads to complete processing data in lock-step.
   */
   Barrier m_input_complete_barrier;

   /*
   * The work that needs to be done. This should be only when the threads
   * are NOT running (i.e. before notifying the work condition, after
   * the input_complete_barrier has reset.)
   */
   const uint8_t* m_input = nullptr;

   /*
   * The length of the work that needs to be done.
   */
   size_t m_input_length = 0;
   };

/*
* Threaded_Fork constructor
*/
Threaded_Fork::Threaded_Fork(Filter* f1, Filter* f2, Filter* f3, Filter* f4) :
   Fork(nullptr, static_cast<size_t>(0)),
   m_thread_data(new Threaded_Fork_Data)
   {
   Filter* filters[4] = { f1, f2, f3, f4 };
   set_next(filters, 4);
   }

/*
* Threaded_Fork constructor
*/
Threaded_Fork::Threaded_Fork(Filter* filters[], size_t count) :
   Fork(nullptr, static_cast<size_t>(0)),
   m_thread_data(new Threaded_Fork_Data)
   {
   set_next(filters, count);
   }

Threaded_Fork::~Threaded_Fork()
   {
   m_thread_data->m_input = nullptr;
   m_thread_data->m_input_length = 0;

   m_thread_data->m_input_ready_semaphore.release(m_threads.size());

   for(auto& thread : m_threads)
     thread->join();
   }

std::string Threaded_Fork::name() const
   {
   return "Threaded Fork";
   }

void Threaded_Fork::set_next(Filter* f[], size_t n)
   {
   Fork::set_next(f, n);
   n = m_next.size();

   if(n < m_threads.size())
      m_threads.resize(n);
   else
      {
      m_threads.reserve(n);
      for(size_t i = m_threads.size(); i != n; ++i)
         {
         m_threads.push_back(
            std::shared_ptr<std::thread>(
               new std::thread(
                  std::bind(&Threaded_Fork::thread_entry, this, m_next[i]))));
         }
      }
   }

void Threaded_Fork::send(const uint8_t input[], size_t length)
   {
   if(m_write_queue.size())
      thread_delegate_work(m_write_queue.data(), m_write_queue.size());
   thread_delegate_work(input, length);

   bool nothing_attached = true;
   for(size_t j = 0; j != total_ports(); ++j)
      if(m_next[j])
         nothing_attached = false;

   if(nothing_attached)
      m_write_queue += std::make_pair(input, length);
   else
      m_write_queue.clear();
   }

void Threaded_Fork::thread_delegate_work(const uint8_t input[], size_t length)
   {
   //Set the data to do.
   m_thread_data->m_input = input;
   m_thread_data->m_input_length = length;

   //Let the workers start processing.
   m_thread_data->m_input_complete_barrier.wait(total_ports() + 1);
   m_thread_data->m_input_ready_semaphore.release(total_ports());

   //Wait for all the filters to finish processing.
   m_thread_data->m_input_complete_barrier.sync();

   //Reset the thread data
   m_thread_data->m_input = nullptr;
   m_thread_data->m_input_length = 0;
   }

void Threaded_Fork::thread_entry(Filter* filter)
   {
   while(true)
      {
      m_thread_data->m_input_ready_semaphore.acquire();

      if(!m_thread_data->m_input)
         break;

      filter->write(m_thread_data->m_input, m_thread_data->m_input_length);
      m_thread_data->m_input_complete_barrier.sync();
      }
   }

}

#endif
/*
* Hex Encoding and Decoding
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

void hex_encode(char output[],
                const uint8_t input[],
                size_t input_length,
                bool uppercase)
   {
   static const uint8_t BIN_TO_HEX_UPPER[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'A', 'B', 'C', 'D', 'E', 'F' };

   static const uint8_t BIN_TO_HEX_LOWER[16] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f' };

   const uint8_t* tbl = uppercase ? BIN_TO_HEX_UPPER : BIN_TO_HEX_LOWER;

   for(size_t i = 0; i != input_length; ++i)
      {
      uint8_t x = input[i];
      output[2*i  ] = tbl[(x >> 4) & 0x0F];
      output[2*i+1] = tbl[(x     ) & 0x0F];
      }
   }

std::string hex_encode(const uint8_t input[],
                       size_t input_length,
                       bool uppercase)
   {
   std::string output(2 * input_length, 0);

   if(input_length)
      hex_encode(&output.front(), input, input_length, uppercase);

   return output;
   }

size_t hex_decode(uint8_t output[],
                  const char input[],
                  size_t input_length,
                  size_t& input_consumed,
                  bool ignore_ws)
   {
   /*
   * Mapping of hex characters to either their binary equivalent
   * or to an error code.
   *  If valid hex (0-9 A-F a-f), the value.
   *  If whitespace, then 0x80
   *  Otherwise 0xFF
   * Warning: this table assumes ASCII character encodings
   */

   static const uint8_t HEX_TO_BIN[256] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x80,
      0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01,
      0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
      0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C,
      0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

   uint8_t* out_ptr = output;
   bool top_nibble = true;

   clear_mem(output, input_length / 2);

   for(size_t i = 0; i != input_length; ++i)
      {
      const uint8_t bin = HEX_TO_BIN[static_cast<uint8_t>(input[i])];

      if(bin >= 0x10)
         {
         if(bin == 0x80 && ignore_ws)
            continue;

         std::string bad_char(1, input[i]);
         if(bad_char == "\t")
           bad_char = "\\t";
         else if(bad_char == "\n")
           bad_char = "\\n";

         throw Invalid_Argument(
           std::string("hex_decode: invalid hex character '") +
           bad_char + "'");
         }

      if(top_nibble)
         *out_ptr |= bin << 4;
      else
         *out_ptr |= bin;

      top_nibble = !top_nibble;
      if(top_nibble)
         ++out_ptr;
      }

   input_consumed = input_length;
   size_t written = (out_ptr - output);

   /*
   * We only got half of a uint8_t at the end; zap the half-written
   * output and mark it as unread
   */
   if(!top_nibble)
      {
      *out_ptr = 0;
      input_consumed -= 1;
      }

   return written;
   }

size_t hex_decode(uint8_t output[],
                  const char input[],
                  size_t input_length,
                  bool ignore_ws)
   {
   size_t consumed = 0;
   size_t written = hex_decode(output, input, input_length,
                               consumed, ignore_ws);

   if(consumed != input_length)
      throw Invalid_Argument("hex_decode: input did not have full bytes");

   return written;
   }

size_t hex_decode(uint8_t output[],
                  const std::string& input,
                  bool ignore_ws)
   {
   return hex_decode(output, input.data(), input.length(), ignore_ws);
   }

secure_vector<uint8_t> hex_decode_locked(const char input[],
                                      size_t input_length,
                                      bool ignore_ws)
   {
   secure_vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(),
                               input,
                               input_length,
                               ignore_ws);

   bin.resize(written);
   return bin;
   }

secure_vector<uint8_t> hex_decode_locked(const std::string& input,
                                      bool ignore_ws)
   {
   return hex_decode_locked(input.data(), input.size(), ignore_ws);
   }

std::vector<uint8_t> hex_decode(const char input[],
                             size_t input_length,
                             bool ignore_ws)
   {
   std::vector<uint8_t> bin(1 + input_length / 2);

   size_t written = hex_decode(bin.data(),
                               input,
                               input_length,
                               ignore_ws);

   bin.resize(written);
   return bin;
   }

std::vector<uint8_t> hex_decode(const std::string& input,
                             bool ignore_ws)
   {
   return hex_decode(input.data(), input.size(), ignore_ws);
   }

}
/*
* IDEA
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace {

/*
* Multiplication modulo 65537
*/
inline uint16_t mul(uint16_t x, uint16_t y)
   {
   const uint32_t P = static_cast<uint32_t>(x) * y;
   const auto P_mask = CT::Mask<uint16_t>(CT::Mask<uint32_t>::is_zero(P));

   const uint32_t P_hi = P >> 16;
   const uint32_t P_lo = P & 0xFFFF;

   const uint16_t carry = (P_lo < P_hi);
   const uint16_t r_1 = static_cast<uint16_t>((P_lo - P_hi) + carry);
   const uint16_t r_2 = 1 - x - y;

   return P_mask.select(r_2, r_1);
   }

/*
* Find multiplicative inverses modulo 65537
*
* 65537 is prime; thus Fermat's little theorem tells us that
* x^65537 == x modulo 65537, which means
* x^(65537-2) == x^-1 modulo 65537 since
* x^(65537-2) * x == 1 mod 65537
*
* Do the exponentiation with a basic square and multiply: all bits are
* of exponent are 1 so we always multiply
*/
uint16_t mul_inv(uint16_t x)
   {
   uint16_t y = x;

   for(size_t i = 0; i != 15; ++i)
      {
      y = mul(y, y); // square
      y = mul(y, x);
      }

   return y;
   }

/**
* IDEA is involutional, depending only on the key schedule
*/
void idea_op(const uint8_t in[], uint8_t out[], size_t blocks, const uint16_t K[52])
   {
   const size_t BLOCK_SIZE = 8;

   CT::poison(in, blocks * 8);
   CT::poison(out, blocks * 8);
   CT::poison(K, 52);

   BOTAN_PARALLEL_FOR(size_t i = 0; i < blocks; ++i)
      {
      uint16_t X1, X2, X3, X4;
      load_be(in + BLOCK_SIZE*i, X1, X2, X3, X4);

      for(size_t j = 0; j != 8; ++j)
         {
         X1 = mul(X1, K[6*j+0]);
         X2 += K[6*j+1];
         X3 += K[6*j+2];
         X4 = mul(X4, K[6*j+3]);

         const uint16_t T0 = X3;
         X3 = mul(X3 ^ X1, K[6*j+4]);

         const uint16_t T1 = X2;
         X2 = mul((X2 ^ X4) + X3, K[6*j+5]);
         X3 += X2;

         X1 ^= X2;
         X4 ^= X3;
         X2 ^= T0;
         X3 ^= T1;
         }

      X1  = mul(X1, K[48]);
      X2 += K[50];
      X3 += K[49];
      X4  = mul(X4, K[51]);

      store_be(out + BLOCK_SIZE*i, X1, X3, X2, X4);
      }

   CT::unpoison(in, blocks * 8);
   CT::unpoison(out, blocks * 8);
   CT::unpoison(K, 52);
   }

}

size_t IDEA::parallelism() const
   {
#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2())
      {
      return 8;
      }
#endif

   return 1;
   }

std::string IDEA::provider() const
   {
#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2())
      {
      return "sse2";
      }
#endif

   return "base";
   }

/*
* IDEA Encryption
*/
void IDEA::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_EK.empty() == false);

#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2())
      {
      while(blocks >= 8)
         {
         sse2_idea_op_8(in, out, m_EK.data());
         in += 8 * BLOCK_SIZE;
         out += 8 * BLOCK_SIZE;
         blocks -= 8;
         }
      }
#endif

   idea_op(in, out, blocks, m_EK.data());
   }

/*
* IDEA Decryption
*/
void IDEA::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const
   {
   verify_key_set(m_DK.empty() == false);

#if defined(BOTAN_HAS_IDEA_SSE2)
   if(CPUID::has_sse2())
      {
      while(blocks >= 8)
         {
         sse2_idea_op_8(in, out, m_DK.data());
         in += 8 * BLOCK_SIZE;
         out += 8 * BLOCK_SIZE;
         blocks -= 8;
         }
      }
#endif

   idea_op(in, out, blocks, m_DK.data());
   }

/*
* IDEA Key Schedule
*/
void IDEA::key_schedule(const uint8_t key[], size_t)
   {
   m_EK.resize(52);
   m_DK.resize(52);

   CT::poison(key, 16);
   CT::poison(m_EK.data(), 52);
   CT::poison(m_DK.data(), 52);

   secure_vector<uint64_t> K(2);

   K[0] = load_be<uint64_t>(key, 0);
   K[1] = load_be<uint64_t>(key, 1);

   for(size_t off = 0; off != 48; off += 8)
      {
      for(size_t i = 0; i != 8; ++i)
         m_EK[off+i] = static_cast<uint16_t>(K[i/4] >> (48-16*(i % 4)));

      const uint64_t Kx = (K[0] >> 39);
      const uint64_t Ky = (K[1] >> 39);

      K[0] = (K[0] << 25) | Ky;
      K[1] = (K[1] << 25) | Kx;
      }

   for(size_t i = 0; i != 4; ++i)
      m_EK[48+i] = static_cast<uint16_t>(K[i/4] >> (48-16*(i % 4)));

   m_DK[0] = mul_inv(m_EK[48]);
   m_DK[1] = -m_EK[49];
   m_DK[2] = -m_EK[50];
   m_DK[3] = mul_inv(m_EK[51]);

   for(size_t i = 0; i != 8*6; i += 6)
      {
      m_DK[i+4] = m_EK[46-i];
      m_DK[i+5] = m_EK[47-i];
      m_DK[i+6] = mul_inv(m_EK[42-i]);
      m_DK[i+7] = -m_EK[44-i];
      m_DK[i+8] = -m_EK[43-i];
      m_DK[i+9] = mul_inv(m_EK[45-i]);
      }

   std::swap(m_DK[49], m_DK[50]);

   CT::unpoison(key, 16);
   CT::unpoison(m_EK.data(), 52);
   CT::unpoison(m_DK.data(), 52);
   }

void IDEA::clear()
   {
   zap(m_EK);
   zap(m_DK);
   }

}
/*
* Cipher Modes
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <sstream>

#if defined(BOTAN_HAS_BLOCK_CIPHER)
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
#endif

#if defined(BOTAN_HAS_MODE_CBC)
#endif

#if defined(BOTAN_HAS_MODE_CFB)
#endif

#if defined(BOTAN_HAS_MODE_XTS)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

#if defined(BOTAN_HAS_COMMONCRYPTO)
#endif

namespace Botan {

std::unique_ptr<Cipher_Mode> Cipher_Mode::create_or_throw(const std::string& algo,
                                                          Cipher_Dir direction,
                                                          const std::string& provider)
   {
   if(auto mode = Cipher_Mode::create(algo, direction, provider))
      return mode;

   throw Lookup_Error("Cipher mode", algo, provider);
   }

std::unique_ptr<Cipher_Mode> Cipher_Mode::create(const std::string& algo,
                                                 Cipher_Dir direction,
                                                 const std::string& provider)
   {
#if defined(BOTAN_HAS_COMMONCRYPTO)
   if(provider.empty() || provider == "commoncrypto")
      {
      std::unique_ptr<Cipher_Mode> commoncrypto_cipher(make_commoncrypto_cipher_mode(algo, direction));

      if(commoncrypto_cipher)
         return commoncrypto_cipher;

      if(!provider.empty())
         return std::unique_ptr<Cipher_Mode>();
      }
#endif

#if defined(BOTAN_HAS_OPENSSL)
   if(provider.empty() || provider == "openssl")
      {
      std::unique_ptr<Cipher_Mode> openssl_cipher(make_openssl_cipher_mode(algo, direction));

      if(openssl_cipher)
         return openssl_cipher;

      if(!provider.empty())
         return std::unique_ptr<Cipher_Mode>();
      }
#endif

#if defined(BOTAN_HAS_STREAM_CIPHER)
   if(auto sc = StreamCipher::create(algo))
      {
      return std::unique_ptr<Cipher_Mode>(new Stream_Cipher_Mode(sc.release()));
      }
#endif

#if defined(BOTAN_HAS_AEAD_MODES)
   if(auto aead = AEAD_Mode::create(algo, direction))
      {
      return std::unique_ptr<Cipher_Mode>(aead.release());
      }
#endif

   if(algo.find('/') != std::string::npos)
      {
      const std::vector<std::string> algo_parts = split_on(algo, '/');
      const std::string cipher_name = algo_parts[0];
      const std::vector<std::string> mode_info = parse_algorithm_name(algo_parts[1]);

      if(mode_info.empty())
         return std::unique_ptr<Cipher_Mode>();

      std::ostringstream alg_args;

      alg_args << '(' << cipher_name;
      for(size_t i = 1; i < mode_info.size(); ++i)
         alg_args << ',' << mode_info[i];
      for(size_t i = 2; i < algo_parts.size(); ++i)
         alg_args << ',' << algo_parts[i];
      alg_args << ')';

      const std::string mode_name = mode_info[0] + alg_args.str();
      return Cipher_Mode::create(mode_name, direction, provider);
      }

#if defined(BOTAN_HAS_BLOCK_CIPHER)

   SCAN_Name spec(algo);

   if(spec.arg_count() == 0)
      {
      return std::unique_ptr<Cipher_Mode>();
      }

   std::unique_ptr<BlockCipher> bc(BlockCipher::create(spec.arg(0), provider));

   if(!bc)
      {
      return std::unique_ptr<Cipher_Mode>();
      }

#if defined(BOTAN_HAS_MODE_CBC)
   if(spec.algo_name() == "CBC")
      {
      const std::string padding = spec.arg(1, "PKCS7");

      if(padding == "CTS")
         {
         if(direction == ENCRYPTION)
            return std::unique_ptr<Cipher_Mode>(new CTS_Encryption(bc.release()));
         else
            return std::unique_ptr<Cipher_Mode>(new CTS_Decryption(bc.release()));
         }
      else
         {
         std::unique_ptr<BlockCipherModePaddingMethod> pad(get_bc_pad(padding));

         if(pad)
            {
            if(direction == ENCRYPTION)
               return std::unique_ptr<Cipher_Mode>(new CBC_Encryption(bc.release(), pad.release()));
            else
               return std::unique_ptr<Cipher_Mode>(new CBC_Decryption(bc.release(), pad.release()));
            }
         }
      }
#endif

#if defined(BOTAN_HAS_MODE_XTS)
   if(spec.algo_name() == "XTS")
      {
      if(direction == ENCRYPTION)
         return std::unique_ptr<Cipher_Mode>(new XTS_Encryption(bc.release()));
      else
         return std::unique_ptr<Cipher_Mode>(new XTS_Decryption(bc.release()));
      }
#endif

#if defined(BOTAN_HAS_MODE_CFB)
   if(spec.algo_name() == "CFB")
      {
      const size_t feedback_bits = spec.arg_as_integer(1, 8*bc->block_size());
      if(direction == ENCRYPTION)
         return std::unique_ptr<Cipher_Mode>(new CFB_Encryption(bc.release(), feedback_bits));
      else
         return std::unique_ptr<Cipher_Mode>(new CFB_Decryption(bc.release(), feedback_bits));
      }
#endif

#endif

   return std::unique_ptr<Cipher_Mode>();
   }

//static
std::vector<std::string> Cipher_Mode::providers(const std::string& algo_spec)
   {
   const std::vector<std::string>& possible = { "base", "openssl", "commoncrypto" };
   std::vector<std::string> providers;
   for(auto&& prov : possible)
      {
      std::unique_ptr<Cipher_Mode> mode = Cipher_Mode::create(algo_spec, ENCRYPTION, prov);
      if(mode)
         {
         providers.push_back(prov); // available
         }
      }
   return providers;
   }

}
/*
* OFB Mode
* (C) 1999-2007,2014 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

OFB::OFB(BlockCipher* cipher) :
   m_cipher(cipher),
   m_buffer(m_cipher->block_size()),
   m_buf_pos(0)
   {
   }

void OFB::clear()
   {
   m_cipher->clear();
   zeroise(m_buffer);
   m_buf_pos = 0;
   }

void OFB::key_schedule(const uint8_t key[], size_t key_len)
   {
   m_cipher->set_key(key, key_len);

   // Set a default all-zeros IV
   set_iv(nullptr, 0);
   }

std::string OFB::name() const
   {
   return "OFB(" + m_cipher->name() + ")";
   }

size_t OFB::default_iv_length() const
   {
   return m_cipher->block_size();
   }

bool OFB::valid_iv_length(size_t iv_len) const
   {
   return (iv_len <= m_cipher->block_size());
   }

Key_Length_Specification OFB::key_spec() const
   {
   return m_cipher->key_spec();
   }

OFB* OFB::clone() const
   {
   return new OFB(m_cipher->clone());
   }

void OFB::cipher(const uint8_t in[], uint8_t out[], size_t length)
   {
   while(length >= m_buffer.size() - m_buf_pos)
      {
      xor_buf(out, in, &m_buffer[m_buf_pos], m_buffer.size() - m_buf_pos);
      length -= (m_buffer.size() - m_buf_pos);
      in += (m_buffer.size() - m_buf_pos);
      out += (m_buffer.size() - m_buf_pos);
      m_cipher->encrypt(m_buffer);
      m_buf_pos = 0;
      }
   xor_buf(out, in, &m_buffer[m_buf_pos], length);
   m_buf_pos += length;
   }

void OFB::set_iv(const uint8_t iv[], size_t iv_len)
   {
   if(!valid_iv_length(iv_len))
      throw Invalid_IV_Length(name(), iv_len);

   zeroise(m_buffer);
   buffer_insert(m_buffer, 0, iv, iv_len);

   m_cipher->encrypt(m_buffer);
   m_buf_pos = 0;
   }


void OFB::seek(uint64_t)
   {
   throw Not_Implemented("OFB does not support seeking");
   }
}
/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
#endif

namespace Botan {

void RandomNumberGenerator::randomize_with_ts_input(uint8_t output[], size_t output_len)
   {
   if(this->accepts_input())
      {
      /*
      Form additional input which is provided to the PRNG implementation
      to paramaterize the KDF output.
      */
      uint8_t additional_input[16] = { 0 };
      store_le(OS::get_system_timestamp_ns(), additional_input);
      store_le(OS::get_high_resolution_clock(), additional_input + 8);

      this->randomize_with_input(output, output_len, additional_input, sizeof(additional_input));
      }
   else
      {
      this->randomize(output, output_len);
      }
   }

void RandomNumberGenerator::randomize_with_input(uint8_t output[], size_t output_len,
                                                 const uint8_t input[], size_t input_len)
   {
   this->add_entropy(input, input_len);
   this->randomize(output, output_len);
   }

size_t RandomNumberGenerator::reseed(Entropy_Sources& srcs,
                                     size_t poll_bits,
                                     std::chrono::milliseconds poll_timeout)
   {
   if(this->accepts_input())
      {
      return srcs.poll(*this, poll_bits, poll_timeout);
      }
   else
      {
      return 0;
      }
   }

void RandomNumberGenerator::reseed_from_rng(RandomNumberGenerator& rng, size_t poll_bits)
   {
   if(this->accepts_input())
      {
      secure_vector<uint8_t> buf(poll_bits / 8);
      rng.randomize(buf.data(), buf.size());
      this->add_entropy(buf.data(), buf.size());
      }
   }

RandomNumberGenerator* RandomNumberGenerator::make_rng()
   {
#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
   return new AutoSeeded_RNG;
#else
   throw Not_Implemented("make_rng failed, no AutoSeeded_RNG in this build");
#endif
   }

#if defined(BOTAN_TARGET_OS_HAS_THREADS)

#if defined(BOTAN_HAS_AUTO_SEEDING_RNG)
Serialized_RNG::Serialized_RNG() : m_rng(new AutoSeeded_RNG) {}
#else
Serialized_RNG::Serialized_RNG()
   {
   throw Not_Implemented("Serialized_RNG default constructor failed: AutoSeeded_RNG disabled in build");
   }
#endif

#endif

}
/*
* Stream Ciphers
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_HAS_CHACHA)
#endif

#if defined(BOTAN_HAS_SALSA20)
#endif

#if defined(BOTAN_HAS_SHAKE_CIPHER)
#endif

#if defined(BOTAN_HAS_CTR_BE)
#endif

#if defined(BOTAN_HAS_OFB)
#endif

#if defined(BOTAN_HAS_RC4)
#endif

#if defined(BOTAN_HAS_OPENSSL)
#endif

namespace Botan {

std::unique_ptr<StreamCipher> StreamCipher::create(const std::string& algo_spec,
                                                   const std::string& provider)
   {
   const SCAN_Name req(algo_spec);

#if defined(BOTAN_HAS_CTR_BE)
   if((req.algo_name() == "CTR-BE" || req.algo_name() == "CTR") && req.arg_count_between(1,2))
      {
      if(provider.empty() || provider == "base")
         {
         auto cipher = BlockCipher::create(req.arg(0));
         if(cipher)
            {
            size_t ctr_size = req.arg_as_integer(1, cipher->block_size());
            return std::unique_ptr<StreamCipher>(new CTR_BE(cipher.release(), ctr_size));
            }
         }
      }
#endif

#if defined(BOTAN_HAS_CHACHA)
   if(req.algo_name() == "ChaCha")
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<StreamCipher>(new ChaCha(req.arg_as_integer(0, 20)));
      }

   if(req.algo_name() == "ChaCha20")
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<StreamCipher>(new ChaCha(20));
      }
#endif

#if defined(BOTAN_HAS_SALSA20)
   if(req.algo_name() == "Salsa20")
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<StreamCipher>(new Salsa20);
      }
#endif

#if defined(BOTAN_HAS_SHAKE_CIPHER)
   if(req.algo_name() == "SHAKE-128" || req.algo_name() == "SHAKE-128-XOF")
      {
      if(provider.empty() || provider == "base")
         return std::unique_ptr<StreamCipher>(new SHAKE_128_Cipher);
      }
#endif

#if defined(BOTAN_HAS_OFB)
   if(req.algo_name() == "OFB" && req.arg_count() == 1)
      {
      if(provider.empty() || provider == "base")
         {
         if(auto c = BlockCipher::create(req.arg(0)))
            return std::unique_ptr<StreamCipher>(new OFB(c.release()));
         }
      }
#endif

#if defined(BOTAN_HAS_RC4)

   if(req.algo_name() == "RC4" ||
      req.algo_name() == "ARC4" ||
      req.algo_name() == "MARK-4")
      {
      const size_t skip = (req.algo_name() == "MARK-4") ? 256 : req.arg_as_integer(0, 0);

#if defined(BOTAN_HAS_OPENSSL)
      if(provider.empty() || provider == "openssl")
         {
         return std::unique_ptr<StreamCipher>(make_openssl_rc4(skip));
         }
#endif

      if(provider.empty() || provider == "base")
         {
         return std::unique_ptr<StreamCipher>(new RC4(skip));
         }
      }

#endif

   BOTAN_UNUSED(req);
   BOTAN_UNUSED(provider);

   return nullptr;
   }

//static
std::unique_ptr<StreamCipher>
StreamCipher::create_or_throw(const std::string& algo,
                             const std::string& provider)
   {
   if(auto sc = StreamCipher::create(algo, provider))
      {
      return sc;
      }
   throw Lookup_Error("Stream cipher", algo, provider);
   }

std::vector<std::string> StreamCipher::providers(const std::string& algo_spec)
   {
   return probe_providers_of<StreamCipher>(algo_spec, {"base", "openssl"});
   }

}
/*
* Runtime assertion checking
* (C) 2010,2012,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

void throw_invalid_argument(const char* message,
                            const char* func,
                            const char* file)
   {
   std::ostringstream format;
   format << message << " in " << func << ":" << file;
   throw Invalid_Argument(format.str());
   }

void throw_invalid_state(const char* expr,
                         const char* func,
                         const char* file)
   {
   std::ostringstream format;
   format << "Invalid state: " << expr << " was false in " << func << ":" << file;
   throw Invalid_State(format.str());
   }

void assertion_failure(const char* expr_str,
                       const char* assertion_made,
                       const char* func,
                       const char* file,
                       int line)
   {
   std::ostringstream format;

   format << "False assertion ";

   if(assertion_made && assertion_made[0] != 0)
      format << "'" << assertion_made << "' (expression " << expr_str << ") ";
   else
      format << expr_str << " ";

   if(func)
      format << "in " << func << " ";

   format << "@" << file << ":" << line;

   throw Internal_Error(format.str());
   }

}
/*
* Calendar Functions
* (C) 1999-2010,2017 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <ctime>
#include <iomanip>
#include <stdlib.h>

namespace Botan {

namespace {

std::tm do_gmtime(std::time_t time_val)
   {
   std::tm tm;

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   ::gmtime_s(&tm, &time_val); // Windows
#elif defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::gmtime_r(&time_val, &tm); // Unix/SUSv2
#else
   std::tm* tm_p = std::gmtime(&time_val);
   if (tm_p == nullptr)
      throw Encoding_Error("time_t_to_tm could not convert");
   tm = *tm_p;
#endif

   return tm;
   }

/*
Portable replacement for timegm, _mkgmtime, etc

Algorithm due to Howard Hinnant

See https://howardhinnant.github.io/date_algorithms.html#days_from_civil
for details and explaination. The code is slightly simplified by our assumption
that the date is at least 1970, which is sufficient for our purposes.
*/
size_t days_since_epoch(uint32_t year, uint32_t month, uint32_t day)
   {
   if(month <= 2)
      year -= 1;
   const uint32_t era = year / 400;
   const uint32_t yoe = year - era * 400;      // [0, 399]
   const uint32_t doy = (153*(month + (month > 2 ? -3 : 9)) + 2)/5 + day-1;  // [0, 365]
   const uint32_t doe = yoe * 365 + yoe/4 - yoe/100 + doy;         // [0, 146096]
   return era * 146097 + doe - 719468;
   }

}

std::chrono::system_clock::time_point calendar_point::to_std_timepoint() const
   {
   if(get_year() < 1970)
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years before 1970");

   // 32 bit time_t ends at January 19, 2038
   // https://msdn.microsoft.com/en-us/library/2093ets1.aspx
   // Throw after 2037 if 32 bit time_t is used

   BOTAN_IF_CONSTEXPR(sizeof(std::time_t) == 4)
      {
      if(get_year() > 2037)
         {
         throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2037 on this system");
         }
      }

   // This upper bound is completely arbitrary
   if(get_year() >= 2400)
      {
      throw Invalid_Argument("calendar_point::to_std_timepoint() does not support years after 2400");
      }

   const uint64_t seconds_64 = (days_since_epoch(get_year(), get_month(), get_day()) * 86400) +
                                (get_hour() * 60 * 60) + (get_minutes() * 60) + get_seconds();

   const time_t seconds_time_t = static_cast<time_t>(seconds_64);

   if(seconds_64 - seconds_time_t != 0)
      {
      throw Invalid_Argument("calendar_point::to_std_timepoint time_t overflow");
      }

   return std::chrono::system_clock::from_time_t(seconds_time_t);
   }

std::string calendar_point::to_string() const
   {
   // desired format: <YYYY>-<MM>-<dd>T<HH>:<mm>:<ss>
   std::stringstream output;
   output << std::setfill('0')
          << std::setw(4) << get_year() << "-"
          << std::setw(2) << get_month() << "-"
          << std::setw(2) << get_day() << "T"
          << std::setw(2) << get_hour() << ":"
          << std::setw(2) << get_minutes() << ":"
          << std::setw(2) << get_seconds();
   return output.str();
   }


calendar_point calendar_value(
   const std::chrono::system_clock::time_point& time_point)
   {
   std::tm tm = do_gmtime(std::chrono::system_clock::to_time_t(time_point));

   return calendar_point(tm.tm_year + 1900,
                         tm.tm_mon + 1,
                         tm.tm_mday,
                         tm.tm_hour,
                         tm.tm_min,
                         tm.tm_sec);
   }

}
/*
* Character Set Handling
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <cctype>

namespace Botan {

namespace {

void append_utf8_for(std::string& s, uint32_t c)
   {
   if(c >= 0xD800 && c < 0xE000)
      throw Decoding_Error("Invalid Unicode character");

   if(c <= 0x7F)
      {
      const uint8_t b0 = static_cast<uint8_t>(c);
      s.push_back(static_cast<char>(b0));
      }
   else if(c <= 0x7FF)
      {
      const uint8_t b0 = 0xC0 | static_cast<uint8_t>(c >> 6);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      }
   else if(c <= 0xFFFF)
      {
      const uint8_t b0 = 0xE0 | static_cast<uint8_t>(c >> 12);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
      }
   else if(c <= 0x10FFFF)
      {
      const uint8_t b0 = 0xF0 | static_cast<uint8_t>(c >> 18);
      const uint8_t b1 = 0x80 | static_cast<uint8_t>((c >> 12) & 0x3F);
      const uint8_t b2 = 0x80 | static_cast<uint8_t>((c >> 6) & 0x3F);
      const uint8_t b3 = 0x80 | static_cast<uint8_t>(c & 0x3F);
      s.push_back(static_cast<char>(b0));
      s.push_back(static_cast<char>(b1));
      s.push_back(static_cast<char>(b2));
      s.push_back(static_cast<char>(b3));
      }
   else
      throw Decoding_Error("Invalid Unicode character");

   }

}

std::string ucs2_to_utf8(const uint8_t ucs2[], size_t len)
   {
   if(len % 2 != 0)
      throw Decoding_Error("Invalid length for UCS-2 string");

   const size_t chars = len / 2;

   std::string s;
   for(size_t i = 0; i != chars; ++i)
      {
      const uint16_t c = load_be<uint16_t>(ucs2, i);
      append_utf8_for(s, c);
      }

   return s;
   }

std::string ucs4_to_utf8(const uint8_t ucs4[], size_t len)
   {
   if(len % 4 != 0)
      throw Decoding_Error("Invalid length for UCS-4 string");

   const size_t chars = len / 4;

   std::string s;
   for(size_t i = 0; i != chars; ++i)
      {
      const uint32_t c = load_be<uint32_t>(ucs4, i);
      append_utf8_for(s, c);
      }

   return s;
   }

/*
* Convert from UTF-8 to ISO 8859-1
*/
std::string utf8_to_latin1(const std::string& utf8)
   {
   std::string iso8859;

   size_t position = 0;
   while(position != utf8.size())
      {
      const uint8_t c1 = static_cast<uint8_t>(utf8[position++]);

      if(c1 <= 0x7F)
         {
         iso8859 += static_cast<char>(c1);
         }
      else if(c1 >= 0xC0 && c1 <= 0xC7)
         {
         if(position == utf8.size())
            throw Decoding_Error("UTF-8: sequence truncated");

         const uint8_t c2 = static_cast<uint8_t>(utf8[position++]);
         const uint8_t iso_char = ((c1 & 0x07) << 6) | (c2 & 0x3F);

         if(iso_char <= 0x7F)
            throw Decoding_Error("UTF-8: sequence longer than needed");

         iso8859 += static_cast<char>(iso_char);
         }
      else
         throw Decoding_Error("UTF-8: Unicode chars not in Latin1 used");
      }

   return iso8859;
   }

namespace Charset {

namespace {

/*
* Convert from UCS-2 to ISO 8859-1
*/
std::string ucs2_to_latin1(const std::string& ucs2)
   {
   if(ucs2.size() % 2 == 1)
      throw Decoding_Error("UCS-2 string has an odd number of bytes");

   std::string latin1;

   for(size_t i = 0; i != ucs2.size(); i += 2)
      {
      const uint8_t c1 = ucs2[i];
      const uint8_t c2 = ucs2[i+1];

      if(c1 != 0)
         throw Decoding_Error("UCS-2 has non-Latin1 characters");

      latin1 += static_cast<char>(c2);
      }

   return latin1;
   }

/*
* Convert from ISO 8859-1 to UTF-8
*/
std::string latin1_to_utf8(const std::string& iso8859)
   {
   std::string utf8;
   for(size_t i = 0; i != iso8859.size(); ++i)
      {
      const uint8_t c = static_cast<uint8_t>(iso8859[i]);

      if(c <= 0x7F)
         utf8 += static_cast<char>(c);
      else
         {
         utf8 += static_cast<char>((0xC0 | (c >> 6)));
         utf8 += static_cast<char>((0x80 | (c & 0x3F)));
         }
      }
   return utf8;
   }

}

/*
* Perform character set transcoding
*/
std::string transcode(const std::string& str,
                      Character_Set to, Character_Set from)
   {
   if(to == LOCAL_CHARSET)
      to = LATIN1_CHARSET;
   if(from == LOCAL_CHARSET)
      from = LATIN1_CHARSET;

   if(to == from)
      return str;

   if(from == LATIN1_CHARSET && to == UTF8_CHARSET)
      return latin1_to_utf8(str);
   if(from == UTF8_CHARSET && to == LATIN1_CHARSET)
      return utf8_to_latin1(str);
   if(from == UCS2_CHARSET && to == LATIN1_CHARSET)
      return ucs2_to_latin1(str);

   throw Invalid_Argument("Unknown transcoding operation from " +
                          std::to_string(from) + " to " + std::to_string(to));
   }

/*
* Check if a character represents a digit
*/
bool is_digit(char c)
   {
   if(c == '0' || c == '1' || c == '2' || c == '3' || c == '4' ||
      c == '5' || c == '6' || c == '7' || c == '8' || c == '9')
      return true;
   return false;
   }

/*
* Check if a character represents whitespace
*/
bool is_space(char c)
   {
   if(c == ' ' || c == '\t' || c == '\n' || c == '\r')
      return true;
   return false;
   }

/*
* Convert a character to a digit
*/
uint8_t char2digit(char c)
   {
   switch(c)
      {
      case '0': return 0;
      case '1': return 1;
      case '2': return 2;
      case '3': return 3;
      case '4': return 4;
      case '5': return 5;
      case '6': return 6;
      case '7': return 7;
      case '8': return 8;
      case '9': return 9;
      }

   throw Invalid_Argument("char2digit: Input is not a digit character");
   }

/*
* Convert a digit to a character
*/
char digit2char(uint8_t b)
   {
   switch(b)
      {
      case 0: return '0';
      case 1: return '1';
      case 2: return '2';
      case 3: return '3';
      case 4: return '4';
      case 5: return '5';
      case 6: return '6';
      case 7: return '7';
      case 8: return '8';
      case 9: return '9';
      }

   throw Invalid_Argument("digit2char: Input is not a digit");
   }

/*
* Case-insensitive character comparison
*/
bool caseless_cmp(char a, char b)
   {
   return (std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b)));
   }

}

}
/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

namespace CT {

secure_vector<uint8_t> copy_output(CT::Mask<uint8_t> bad_input,
                                   const uint8_t input[],
                                   size_t input_length,
                                   size_t offset)
   {
   if(input_length == 0)
      return secure_vector<uint8_t>();

   /*
   * Ensure at runtime that offset <= input_length. This is an invalid input,
   * but we can't throw without using the poisoned value. Instead, if it happens,
   * set offset to be equal to the input length (so output_bytes becomes 0 and
   * the returned vector is empty)
   */
   const auto valid_offset = CT::Mask<size_t>::is_lte(offset, input_length);
   offset = valid_offset.select(offset, input_length);

   const size_t output_bytes = input_length - offset;

   secure_vector<uint8_t> output(input_length);

   /*
   Move the desired output bytes to the front using a slow (O^n)
   but constant time loop that does not leak the value of the offset
   */
   for(size_t i = 0; i != input_length; ++i)
      {
      /*
      start index from i rather than 0 since we know j must be >= i + offset
      to have any effect, and starting from i does not reveal information
      */
      for(size_t j = i; j != input_length; ++j)
         {
         const uint8_t b = input[j];
         const auto is_eq = CT::Mask<size_t>::is_equal(j, offset + i);
         output[i] |= is_eq.if_set_return(b);
         }
      }

   bad_input.if_set_zero_out(output.data(), output.size());

   /*
   This is potentially not const time, depending on how std::vector is
   implemented. But since we are always reducing length, it should
   just amount to setting the member var holding the length.
   */
   CT::unpoison(output.data(), output.size());
   CT::unpoison(output_bytes);
   output.resize(output_bytes);
   return output;
   }

secure_vector<uint8_t> strip_leading_zeros(const uint8_t in[], size_t length)
   {
   size_t leading_zeros = 0;

   auto only_zeros = Mask<uint8_t>::set();

   for(size_t i = 0; i != length; ++i)
      {
      only_zeros &= CT::Mask<uint8_t>::is_zero(in[i]);
      leading_zeros += only_zeros.if_set_return(1);
      }

   return copy_output(CT::Mask<uint8_t>::cleared(), in, length, leading_zeros);
   }

}

}
/*
* DataSource
* (C) 1999-2007 Jack Lloyd
*     2005 Matthew Gregan
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)
  #include <fstream>
#endif

namespace Botan {

/*
* Read a single byte from the DataSource
*/
size_t DataSource::read_byte(uint8_t& out)
   {
   return read(&out, 1);
   }

/*
* Peek a single byte from the DataSource
*/
size_t DataSource::peek_byte(uint8_t& out) const
   {
   return peek(&out, 1, 0);
   }

/*
* Discard the next N bytes of the data
*/
size_t DataSource::discard_next(size_t n)
   {
   uint8_t buf[64] = { 0 };
   size_t discarded = 0;

   while(n)
      {
      const size_t got = this->read(buf, std::min(n, sizeof(buf)));
      discarded += got;
      n -= got;

      if(got == 0)
         break;
      }

   return discarded;
   }

/*
* Read from a memory buffer
*/
size_t DataSource_Memory::read(uint8_t out[], size_t length)
   {
   const size_t got = std::min<size_t>(m_source.size() - m_offset, length);
   copy_mem(out, m_source.data() + m_offset, got);
   m_offset += got;
   return got;
   }

bool DataSource_Memory::check_available(size_t n)
   {
   return (n <= (m_source.size() - m_offset));
   }

/*
* Peek into a memory buffer
*/
size_t DataSource_Memory::peek(uint8_t out[], size_t length,
                               size_t peek_offset) const
   {
   const size_t bytes_left = m_source.size() - m_offset;
   if(peek_offset >= bytes_left) return 0;

   const size_t got = std::min(bytes_left - peek_offset, length);
   copy_mem(out, &m_source[m_offset + peek_offset], got);
   return got;
   }

/*
* Check if the memory buffer is empty
*/
bool DataSource_Memory::end_of_data() const
   {
   return (m_offset == m_source.size());
   }

/*
* DataSource_Memory Constructor
*/
DataSource_Memory::DataSource_Memory(const std::string& in) :
   m_source(cast_char_ptr_to_uint8(in.data()),
            cast_char_ptr_to_uint8(in.data()) + in.length()),
   m_offset(0)
   {
   }

/*
* Read from a stream
*/
size_t DataSource_Stream::read(uint8_t out[], size_t length)
   {
   m_source.read(cast_uint8_ptr_to_char(out), length);
   if(m_source.bad())
      throw Stream_IO_Error("DataSource_Stream::read: Source failure");

   const size_t got = static_cast<size_t>(m_source.gcount());
   m_total_read += got;
   return got;
   }

bool DataSource_Stream::check_available(size_t n)
   {
   const std::streampos orig_pos = m_source.tellg();
   m_source.seekg(0, std::ios::end);
   const size_t avail = static_cast<size_t>(m_source.tellg() - orig_pos);
   m_source.seekg(orig_pos);
   return (avail >= n);
   }

/*
* Peek into a stream
*/
size_t DataSource_Stream::peek(uint8_t out[], size_t length, size_t offset) const
   {
   if(end_of_data())
      throw Invalid_State("DataSource_Stream: Cannot peek when out of data");

   size_t got = 0;

   if(offset)
      {
      secure_vector<uint8_t> buf(offset);
      m_source.read(cast_uint8_ptr_to_char(buf.data()), buf.size());
      if(m_source.bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = static_cast<size_t>(m_source.gcount());
      }

   if(got == offset)
      {
      m_source.read(cast_uint8_ptr_to_char(out), length);
      if(m_source.bad())
         throw Stream_IO_Error("DataSource_Stream::peek: Source failure");
      got = static_cast<size_t>(m_source.gcount());
      }

   if(m_source.eof())
      m_source.clear();
   m_source.seekg(m_total_read, std::ios::beg);

   return got;
   }

/*
* Check if the stream is empty or in error
*/
bool DataSource_Stream::end_of_data() const
   {
   return (!m_source.good());
   }

/*
* Return a human-readable ID for this stream
*/
std::string DataSource_Stream::id() const
   {
   return m_identifier;
   }

#if defined(BOTAN_TARGET_OS_HAS_FILESYSTEM)

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(const std::string& path,
                                     bool use_binary) :
   m_identifier(path),
   m_source_memory(new std::ifstream(path, use_binary ? std::ios::binary : std::ios::in)),
   m_source(*m_source_memory),
   m_total_read(0)
   {
   if(!m_source.good())
      {
      throw Stream_IO_Error("DataSource: Failure opening file " + path);
      }
   }

#endif

/*
* DataSource_Stream Constructor
*/
DataSource_Stream::DataSource_Stream(std::istream& in,
                                     const std::string& name) :
   m_identifier(name),
   m_source(in),
   m_total_read(0)
   {
   }

DataSource_Stream::~DataSource_Stream()
   {
   // for ~unique_ptr
   }

}
/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::string to_string(ErrorType type)
   {
   switch(type)
      {
      case ErrorType::Unknown:
         return "Unknown";
      case ErrorType::SystemError:
         return "SystemError";
      case ErrorType::NotImplemented:
         return "NotImplemented";
      case ErrorType::OutOfMemory:
         return "OutOfMemory";
      case ErrorType::InternalError:
         return "InternalError";
      case ErrorType::IoError:
         return "IoError";
      case ErrorType::InvalidObjectState :
         return "InvalidObjectState";
      case ErrorType::KeyNotSet:
         return "KeyNotSet";
      case ErrorType::InvalidArgument:
         return "InvalidArgument";
      case ErrorType::InvalidKeyLength:
         return "InvalidKeyLength";
      case ErrorType::InvalidNonceLength:
         return "InvalidNonceLength";
      case ErrorType::LookupError:
         return "LookupError";
      case ErrorType::EncodingFailure:
         return "EncodingFailure";
      case ErrorType::DecodingFailure:
         return "DecodingFailure";
      case ErrorType::TLSError:
         return "TLSError";
      case ErrorType::HttpError:
         return "HttpError";
      case ErrorType::InvalidTag:
         return "InvalidTag";
      case ErrorType::OpenSSLError :
         return "OpenSSLError";
      case ErrorType::CommonCryptoError:
         return "CommonCryptoError";
      case ErrorType::Pkcs11Error:
         return "Pkcs11Error";
      case ErrorType::TPMError:
         return "TPMError";
      case ErrorType::DatabaseError:
         return "DatabaseError";
      case ErrorType::ZlibError :
         return "ZlibError";
      case ErrorType::Bzip2Error:
         return "Bzip2Error" ;
      case ErrorType::LzmaError:
         return "LzmaError";
      }

   // No default case in above switch so compiler warns
   return "Unrecognized Botan error";
   }

Exception::Exception(const std::string& msg) : m_msg(msg)
   {}

Exception::Exception(const std::string& msg, const std::exception& e) :
   m_msg(msg + " failed with " + std::string(e.what()))
   {}

Exception::Exception(const char* prefix, const std::string& msg) :
   m_msg(std::string(prefix) + " " + msg)
   {}

Invalid_Argument::Invalid_Argument(const std::string& msg) :
   Exception(msg)
   {}

Invalid_Argument::Invalid_Argument(const std::string& msg, const std::string& where) :
   Exception(msg + " in " + where)
   {}

Invalid_Argument::Invalid_Argument(const std::string& msg, const std::exception& e) :
   Exception(msg, e) {}

Lookup_Error::Lookup_Error(const std::string& type,
                           const std::string& algo,
                           const std::string& provider) :
   Exception("Unavailable " + type + " " + algo +
             (provider.empty() ? std::string("") : (" for provider " + provider)))
   {}

Internal_Error::Internal_Error(const std::string& err) :
   Exception("Internal error: " + err)
   {}

Invalid_Key_Length::Invalid_Key_Length(const std::string& name, size_t length) :
   Invalid_Argument(name + " cannot accept a key of length " +
                    std::to_string(length))
   {}

Invalid_IV_Length::Invalid_IV_Length(const std::string& mode, size_t bad_len) :
   Invalid_Argument("IV length " + std::to_string(bad_len) +
                    " is invalid for " + mode)
   {}

Key_Not_Set::Key_Not_Set(const std::string& algo) :
   Invalid_State("Key not set in " + algo)
   {}

Policy_Violation::Policy_Violation(const std::string& err) :
   Invalid_State("Policy violation: " + err) {}

PRNG_Unseeded::PRNG_Unseeded(const std::string& algo) :
   Invalid_State("PRNG not seeded: " + algo)
   {}

Algorithm_Not_Found::Algorithm_Not_Found(const std::string& name) :
   Lookup_Error("Could not find any algorithm named \"" + name + "\"")
   {}

No_Provider_Found::No_Provider_Found(const std::string& name) :
   Exception("Could not find any provider for algorithm named \"" + name + "\"")
   {}

Provider_Not_Found::Provider_Not_Found(const std::string& algo, const std::string& provider) :
   Lookup_Error("Could not find provider '" + provider + "' for " + algo)
   {}

Invalid_Algorithm_Name::Invalid_Algorithm_Name(const std::string& name):
   Invalid_Argument("Invalid algorithm name: " + name)
   {}

Encoding_Error::Encoding_Error(const std::string& name) :
   Invalid_Argument("Encoding error: " + name)
   {}

Decoding_Error::Decoding_Error(const std::string& name) :
   Invalid_Argument(name)
   {}

Decoding_Error::Decoding_Error(const std::string& msg, const std::exception& e) :
   Invalid_Argument(msg, e)
   {}

Decoding_Error::Decoding_Error(const std::string& name, const char* exception_message) :
   Invalid_Argument(name + " failed with exception " + exception_message) {}

Invalid_Authentication_Tag::Invalid_Authentication_Tag(const std::string& msg) :
   Exception("Invalid authentication tag: " + msg)
   {}

Invalid_OID::Invalid_OID(const std::string& oid) :
   Decoding_Error("Invalid ASN.1 OID: " + oid)
   {}

Stream_IO_Error::Stream_IO_Error(const std::string& err) :
   Exception("I/O error: " + err)
   {}

System_Error::System_Error(const std::string& msg, int err_code) :
   Exception(msg + " error code " + std::to_string(err_code)),
   m_error_code(err_code)
   {}

Self_Test_Failure::Self_Test_Failure(const std::string& err) :
   Internal_Error("Self test failed: " + err)
   {}

Not_Implemented::Not_Implemented(const std::string& err) :
   Exception("Not implemented", err)
   {}

}
/*
* (C) 2015,2017,2019 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <dirent.h>
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
  #define NOMINMAX 1
  #define _WINSOCKAPI_ // stop windows.h including winsock.h
  #include <windows.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)

std::vector<std::string> impl_readdir(const std::string& dir_path)
   {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(dir_path);

   while(!dir_list.empty())
      {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      std::unique_ptr<DIR, std::function<int (DIR*)>> dir(::opendir(cur_path.c_str()), ::closedir);

      if(dir)
         {
         while(struct dirent* dirent = ::readdir(dir.get()))
            {
            const std::string filename = dirent->d_name;
            if(filename == "." || filename == "..")
               continue;
            const std::string full_path = cur_path + "/" + filename;

            struct stat stat_buf;

            if(::stat(full_path.c_str(), &stat_buf) == -1)
               continue;

            if(S_ISDIR(stat_buf.st_mode))
               dir_list.push_back(full_path);
            else if(S_ISREG(stat_buf.st_mode))
               out.push_back(full_path);
            }
         }
      }

   return out;
   }

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)

std::vector<std::string> impl_win32(const std::string& dir_path)
   {
   std::vector<std::string> out;
   std::deque<std::string> dir_list;
   dir_list.push_back(dir_path);

   while(!dir_list.empty())
      {
      const std::string cur_path = dir_list[0];
      dir_list.pop_front();

      WIN32_FIND_DATAA find_data;
      HANDLE dir = ::FindFirstFileA((cur_path + "/*").c_str(), &find_data);

      if(dir != INVALID_HANDLE_VALUE)
         {
         do
            {
            const std::string filename = find_data.cFileName;
            if(filename == "." || filename == "..")
               continue;
            const std::string full_path = cur_path + "/" + filename;

            if(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
               {
               dir_list.push_back(full_path);
               }
            else
               {
               out.push_back(full_path);
               }
            }
         while(::FindNextFileA(dir, &find_data));
         }

      ::FindClose(dir);
      }

   return out;
}
#endif

}

bool has_filesystem_impl()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return true;
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   return true;
#else
   return false;
#endif
   }

std::vector<std::string> get_files_recursive(const std::string& dir)
   {
   std::vector<std::string> files;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   files = impl_readdir(dir);
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   files = impl_win32(dir);
#else
   BOTAN_UNUSED(dir);
   throw No_Filesystem_Access();
#endif

   std::sort(files.begin(), files.end());

   return files;
   }

}
/*
* (C) 2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <cstdlib>
#include <new>

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
#endif

namespace Botan {

BOTAN_MALLOC_FN void* allocate_memory(size_t elems, size_t elem_size)
   {
   if(elems == 0 || elem_size == 0)
      return nullptr;

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(void* p = mlock_allocator::instance().allocate(elems, elem_size))
      return p;
#endif

   void* ptr = std::calloc(elems, elem_size);
   if(!ptr)
      throw std::bad_alloc();
   return ptr;
   }

void deallocate_memory(void* p, size_t elems, size_t elem_size)
   {
   if(p == nullptr)
      return;

   secure_scrub_memory(p, elems * elem_size);

#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   if(mlock_allocator::instance().deallocate(p, elems, elem_size))
      return;
#endif

   std::free(p);
   }

void initialize_allocator()
   {
#if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
   mlock_allocator::instance();
#endif
   }

uint8_t ct_compare_u8(const uint8_t x[],
                      const uint8_t y[],
                      size_t len)
   {
   volatile uint8_t difference = 0;

   for(size_t i = 0; i != len; ++i)
      difference |= (x[i] ^ y[i]);

   return CT::Mask<uint8_t>::is_zero(difference).value();
   }

}
/*
* OS and machine specific utility functions
* (C) 2015,2016,2017,2018 Jack Lloyd
* (C) 2016 Daniel Neus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/



#if defined(BOTAN_TARGET_OS_HAS_THREADS)
  #include <thread>
#endif

#if defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
  #include <string.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
  #include <sys/types.h>
  #include <sys/resource.h>
  #include <sys/mman.h>
  #include <signal.h>
  #include <setjmp.h>
  #include <unistd.h>
  #include <errno.h>
  #include <termios.h>
  #undef B0
#endif

#if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
  #include <emscripten/emscripten.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL) || defined(BOTAN_TARGET_OS_IS_ANDROID) || \
  defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
  #include <sys/auxv.h>
#endif

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
  #define NOMINMAX 1
  #include <windows.h>
#endif

#if defined(BOTAN_TARGET_OS_IS_ANDROID)
  #include <elf.h>
  extern "C" char **environ;
#endif

#if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
  #include <mach/vm_statistics.h>
#endif

namespace Botan {

// Not defined in OS namespace for historical reasons
void secure_scrub_memory(void* ptr, size_t n)
   {
#if defined(BOTAN_TARGET_OS_HAS_RTLSECUREZEROMEMORY)
   ::RtlSecureZeroMemory(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_BZERO)
   ::explicit_bzero(ptr, n);

#elif defined(BOTAN_TARGET_OS_HAS_EXPLICIT_MEMSET)
   (void)::explicit_memset(ptr, 0, n);

#elif defined(BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO) && (BOTAN_USE_VOLATILE_MEMSET_FOR_ZERO == 1)
   /*
   Call memset through a static volatile pointer, which the compiler
   should not elide. This construct should be safe in conforming
   compilers, but who knows. I did confirm that on x86-64 GCC 6.1 and
   Clang 3.8 both create code that saves the memset address in the
   data segment and unconditionally loads and jumps to that address.
   */
   static void* (*const volatile memset_ptr)(void*, int, size_t) = std::memset;
   (memset_ptr)(ptr, 0, n);
#else

   volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);

   for(size_t i = 0; i != n; ++i)
      p[i] = 0;
#endif
   }

uint32_t OS::get_process_id()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return ::getpid();
#elif defined(BOTAN_TARGET_OS_HAS_WIN32)
   return ::GetCurrentProcessId();
#elif defined(BOTAN_TARGET_OS_IS_INCLUDEOS) || defined(BOTAN_TARGET_OS_IS_LLVM)
   return 0; // truly no meaningful value
#else
   #error "Missing get_process_id"
#endif
   }

unsigned long OS::get_auxval(unsigned long id)
   {
#if defined(BOTAN_TARGET_OS_HAS_GETAUXVAL)
   return ::getauxval(id);
#elif defined(BOTAN_TARGET_OS_IS_ANDROID) && defined(BOTAN_TARGET_ARCH_IS_ARM32)

   if(id == 0)
      return 0;

   char **p = environ;

   while(*p++ != nullptr)
      ;

   Elf32_auxv_t *e = reinterpret_cast<Elf32_auxv_t*>(p);

   while(e != nullptr)
      {
      if(e->a_type == id)
         return e->a_un.a_val;
      e++;
      }

   return 0;
#elif defined(BOTAN_TARGET_OS_HAS_ELF_AUX_INFO)
   unsigned long auxinfo = 0;
   ::elf_aux_info(id, &auxinfo, sizeof(auxinfo));
   return auxinfo;
#else
   BOTAN_UNUSED(id);
   return 0;
#endif
   }

bool OS::running_in_privileged_state()
   {
#if defined(AT_SECURE)
   return OS::get_auxval(AT_SECURE) != 0;
#elif defined(BOTAN_TARGET_OS_HAS_POSIX1)
   return (::getuid() != ::geteuid()) || (::getgid() != ::getegid());
#else
   return false;
#endif
   }

uint64_t OS::get_cpu_cycle_counter()
   {
   uint64_t rtc = 0;

#if defined(BOTAN_TARGET_OS_HAS_WIN32)
   LARGE_INTEGER tv;
   ::QueryPerformanceCounter(&tv);
   rtc = tv.QuadPart;

#elif defined(BOTAN_USE_GCC_INLINE_ASM)

#if defined(BOTAN_TARGET_CPU_IS_X86_FAMILY)

   if(CPUID::has_rdtsc())
      {
      uint32_t rtc_low = 0, rtc_high = 0;
      asm volatile("rdtsc" : "=d" (rtc_high), "=a" (rtc_low));
      rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
      }

#elif defined(BOTAN_TARGET_ARCH_IS_PPC64)

   for(;;)
      {
      uint32_t rtc_low = 0, rtc_high = 0, rtc_high2 = 0;
      asm volatile("mftbu %0" : "=r" (rtc_high));
      asm volatile("mftb %0" : "=r" (rtc_low));
      asm volatile("mftbu %0" : "=r" (rtc_high2));

      if(rtc_high == rtc_high2)
         {
         rtc = (static_cast<uint64_t>(rtc_high) << 32) | rtc_low;
         break;
         }
      }

#elif defined(BOTAN_TARGET_ARCH_IS_ALPHA)
   asm volatile("rpcc %0" : "=r" (rtc));

   // OpenBSD does not trap access to the %tick register
#elif defined(BOTAN_TARGET_ARCH_IS_SPARC64) && !defined(BOTAN_TARGET_OS_IS_OPENBSD)
   asm volatile("rd %%tick, %0" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_IA64)
   asm volatile("mov %0=ar.itc" : "=r" (rtc));

#elif defined(BOTAN_TARGET_ARCH_IS_S390X)
   asm volatile("stck 0(%0)" : : "a" (&rtc) : "memory", "cc");

#elif defined(BOTAN_TARGET_ARCH_IS_HPPA)
   asm volatile("mfctl 16,%0" : "=r" (rtc)); // 64-bit only?

#else
   //#warning "OS::get_cpu_cycle_counter not implemented"
#endif

#endif

   return rtc;
   }

size_t OS::get_cpu_total()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(_SC_NPROCESSORS_CONF)
   const long res = ::sysconf(_SC_NPROCESSORS_CONF);
   if(res > 0)
      return static_cast<size_t>(res);
#endif

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   return static_cast<size_t>(std::thread::hardware_concurrency());
#else
   return 1;
#endif
   }

size_t OS::get_cpu_available()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(_SC_NPROCESSORS_ONLN)
   const long res = ::sysconf(_SC_NPROCESSORS_ONLN);
   if(res > 0)
      return static_cast<size_t>(res);
#endif

   return OS::get_cpu_total();
   }

uint64_t OS::get_high_resolution_clock()
   {
   if(uint64_t cpu_clock = OS::get_cpu_cycle_counter())
      return cpu_clock;

#if defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   return emscripten_get_now();
#endif

   /*
   If we got here either we either don't have an asm instruction
   above, or (for x86) RDTSC is not available at runtime. Try some
   clock_gettimes and return the first one that works, or otherwise
   fall back to std::chrono.
   */

#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)

   // The ordering here is somewhat arbitrary...
   const clockid_t clock_types[] = {
#if defined(CLOCK_MONOTONIC_HR)
      CLOCK_MONOTONIC_HR,
#endif
#if defined(CLOCK_MONOTONIC_RAW)
      CLOCK_MONOTONIC_RAW,
#endif
#if defined(CLOCK_MONOTONIC)
      CLOCK_MONOTONIC,
#endif
#if defined(CLOCK_PROCESS_CPUTIME_ID)
      CLOCK_PROCESS_CPUTIME_ID,
#endif
#if defined(CLOCK_THREAD_CPUTIME_ID)
      CLOCK_THREAD_CPUTIME_ID,
#endif
   };

   for(clockid_t clock : clock_types)
      {
      struct timespec ts;
      if(::clock_gettime(clock, &ts) == 0)
         {
         return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
         }
      }
#endif

   // Plain C++11 fallback
   auto now = std::chrono::high_resolution_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

uint64_t OS::get_system_timestamp_ns()
   {
#if defined(BOTAN_TARGET_OS_HAS_CLOCK_GETTIME)
   struct timespec ts;
   if(::clock_gettime(CLOCK_REALTIME, &ts) == 0)
      {
      return (static_cast<uint64_t>(ts.tv_sec) * 1000000000) + static_cast<uint64_t>(ts.tv_nsec);
      }
#endif

   auto now = std::chrono::system_clock::now().time_since_epoch();
   return std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
   }

size_t OS::system_page_size()
   {
   const size_t default_page_size = 4096;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   long p = ::sysconf(_SC_PAGESIZE);
   if(p > 1)
      return static_cast<size_t>(p);
   else
      return default_page_size;
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   SYSTEM_INFO sys_info;
   ::GetSystemInfo(&sys_info);
   return sys_info.dwPageSize;
#else
   return default_page_size;
#endif
   }

size_t OS::get_memory_locking_limit()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK) && defined(RLIMIT_MEMLOCK)
   /*
   * If RLIMIT_MEMLOCK is not defined, likely the OS does not support
   * unprivileged mlock calls.
   *
   * Linux defaults to only 64 KiB of mlockable memory per process
   * (too small) but BSDs offer a small fraction of total RAM (more
   * than we need). Bound the total mlock size to 512 KiB which is
   * enough to run the entire test suite without spilling to non-mlock
   * memory (and thus presumably also enough for many useful
   * programs), but small enough that we should not cause problems
   * even if many processes are mlocking on the same machine.
   */
   const size_t user_req = read_env_variable_sz("BOTAN_MLOCK_POOL_SIZE", BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB);

   const size_t mlock_requested = std::min<size_t>(user_req, BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB);

   if(mlock_requested > 0)
      {
      struct ::rlimit limits;

      ::getrlimit(RLIMIT_MEMLOCK, &limits);

      if(limits.rlim_cur < limits.rlim_max)
         {
         limits.rlim_cur = limits.rlim_max;
         ::setrlimit(RLIMIT_MEMLOCK, &limits);
         ::getrlimit(RLIMIT_MEMLOCK, &limits);
         }

      return std::min<size_t>(limits.rlim_cur, mlock_requested * 1024);
      }

#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   SIZE_T working_min = 0, working_max = 0;
   if(!::GetProcessWorkingSetSize(::GetCurrentProcess(), &working_min, &working_max))
      {
      return 0;
      }

   // According to Microsoft MSDN:
   // The maximum number of pages that a process can lock is equal to the number of pages in its minimum working set minus a small overhead
   // In the book "Windows Internals Part 2": the maximum lockable pages are minimum working set size - 8 pages
   // But the information in the book seems to be inaccurate/outdated
   // I've tested this on Windows 8.1 x64, Windows 10 x64 and Windows 7 x86
   // On all three OS the value is 11 instead of 8
   const size_t overhead = OS::system_page_size() * 11;
   if(working_min > overhead)
      {
      const size_t lockable_bytes = working_min - overhead;
      return std::min<size_t>(lockable_bytes, BOTAN_MLOCK_ALLOCATOR_MAX_LOCKED_KB * 1024);
      }
#endif

   // Not supported on this platform
   return 0;
   }

const char* OS::read_env_variable(const std::string& name)
   {
   if(running_in_privileged_state())
      return nullptr;

   return std::getenv(name.c_str());
   }

size_t OS::read_env_variable_sz(const std::string& name, size_t def)
   {
   if(const char* env = read_env_variable(name))
      {
      try
         {
         const size_t val = std::stoul(env, nullptr);
         return val;
         }
      catch(std::exception&) { /* ignore it */ }
      }

   return def;
   }

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

namespace {

int get_locked_fd()
   {
#if defined(BOTAN_TARGET_OS_IS_IOS) || defined(BOTAN_TARGET_OS_IS_MACOS)
   // On Darwin, tagging anonymous pages allows vmmap to track these.
   // Allowed from 240 to 255 for userland applications
   static constexpr int default_locked_fd = 255;
   int locked_fd = default_locked_fd;

   if(size_t locked_fdl = OS::read_env_variable_sz("BOTAN_LOCKED_FD", default_locked_fd))
      {
      if(locked_fdl < 240 || locked_fdl > 255)
         {
         locked_fdl = default_locked_fd;
         }
      locked_fd = static_cast<int>(locked_fdl);
      }
   return VM_MAKE_TAG(locked_fd);
#else
   return -1;
#endif
   }

}

#endif

std::vector<void*> OS::allocate_locked_pages(size_t count)
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
   static const int locked_fd = get_locked_fd();
#endif

   std::vector<void*> result;
   result.reserve(count);

   const size_t page_size = OS::system_page_size();

   for(size_t i = 0; i != count; ++i)
      {
      void* ptr = nullptr;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)

#if !defined(MAP_ANONYMOUS)
   #define MAP_ANONYMOUS MAP_ANON
#endif

#if !defined(MAP_NOCORE)
#if defined(MAP_CONCEAL)
   #define MAP_NOCORE MAP_CONCEAL
#else
   #define MAP_NOCORE 0
#endif
#endif

#if !defined(PROT_MAX)
   #define PROT_MAX(p) 0
#endif
      const int pflags = PROT_READ | PROT_WRITE;

      ptr = ::mmap(nullptr, 2*page_size,
                   pflags | PROT_MAX(pflags),
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_NOCORE,
                   /*fd=*/locked_fd, /*offset=*/0);

      if(ptr == MAP_FAILED)
         {
         continue;
         }

      // failed to lock
      if(::mlock(ptr, page_size) != 0)
         {
         ::munmap(ptr, 2*page_size);
         continue;
         }

#if defined(MADV_DONTDUMP)
      // we ignore errors here, as DONTDUMP is just a bonus
      ::madvise(ptr, page_size, MADV_DONTDUMP);
#endif

#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
      ptr = ::VirtualAlloc(nullptr, 2*page_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

      if(ptr == nullptr)
         continue;

      if(::VirtualLock(ptr, page_size) == 0)
         {
         ::VirtualFree(ptr, 0, MEM_RELEASE);
         continue;
         }
#endif

      std::memset(ptr, 0, 2*page_size); // zero both data and guard pages

      // Make guard page following the data page
      page_prohibit_access(static_cast<uint8_t*>(ptr) + page_size);

      result.push_back(ptr);
      }

   return result;
   }

void OS::page_allow_access(void* page)
   {
   const size_t page_size = OS::system_page_size();
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::mprotect(page, page_size, PROT_READ | PROT_WRITE);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   DWORD old_perms = 0;
   ::VirtualProtect(page, page_size, PAGE_READWRITE, &old_perms);
   BOTAN_UNUSED(old_perms);
#endif
   }

void OS::page_prohibit_access(void* page)
   {
   const size_t page_size = OS::system_page_size();
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   ::mprotect(page, page_size, PROT_NONE);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
   DWORD old_perms = 0;
   ::VirtualProtect(page, page_size, PAGE_NOACCESS, &old_perms);
   BOTAN_UNUSED(old_perms);
#endif
   }

void OS::free_locked_pages(const std::vector<void*>& pages)
   {
   const size_t page_size = OS::system_page_size();

   for(size_t i = 0; i != pages.size(); ++i)
      {
      void* ptr = pages[i];

      secure_scrub_memory(ptr, page_size);

      // ptr points to the data page, guard page follows
      page_allow_access(static_cast<uint8_t*>(ptr) + page_size);

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && defined(BOTAN_TARGET_OS_HAS_POSIX_MLOCK)
      ::munlock(ptr, page_size);
      ::munmap(ptr, 2*page_size);
#elif defined(BOTAN_TARGET_OS_HAS_VIRTUAL_LOCK)
      ::VirtualUnlock(ptr, page_size);
      ::VirtualFree(ptr, 0, MEM_RELEASE);
#endif
      }
   }

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)

namespace {

static ::sigjmp_buf g_sigill_jmp_buf;

void botan_sigill_handler(int)
   {
   siglongjmp(g_sigill_jmp_buf, /*non-zero return value*/1);
   }

}

#endif

int OS::run_cpu_instruction_probe(std::function<int ()> probe_fn)
   {
   volatile int probe_result = -3;

#if defined(BOTAN_TARGET_OS_HAS_POSIX1) && !defined(BOTAN_TARGET_OS_IS_EMSCRIPTEN)
   struct sigaction old_sigaction;
   struct sigaction sigaction;

   sigaction.sa_handler = botan_sigill_handler;
   sigemptyset(&sigaction.sa_mask);
   sigaction.sa_flags = 0;

   int rc = ::sigaction(SIGILL, &sigaction, &old_sigaction);

   if(rc != 0)
      throw System_Error("run_cpu_instruction_probe sigaction failed", errno);

   rc = sigsetjmp(g_sigill_jmp_buf, /*save sigs*/1);

   if(rc == 0)
      {
      // first call to sigsetjmp
      probe_result = probe_fn();
      }
   else if(rc == 1)
      {
      // non-local return from siglongjmp in signal handler: return error
      probe_result = -1;
      }

   // Restore old SIGILL handler, if any
   rc = ::sigaction(SIGILL, &old_sigaction, nullptr);
   if(rc != 0)
      throw System_Error("run_cpu_instruction_probe sigaction restore failed", errno);

#elif defined(BOTAN_TARGET_OS_IS_WINDOWS) && defined(BOTAN_TARGET_COMPILER_IS_MSVC)

   // Windows SEH
   __try
      {
      probe_result = probe_fn();
      }
   __except(::GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ?
            EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
      {
      probe_result = -1;
      }

#else
   BOTAN_UNUSED(probe_fn);
#endif

   return probe_result;
   }

std::unique_ptr<OS::Echo_Suppression> OS::suppress_echo_on_terminal()
   {
#if defined(BOTAN_TARGET_OS_HAS_POSIX1)
   class POSIX_Echo_Suppression : public Echo_Suppression
      {
      public:
         POSIX_Echo_Suppression()
            {
            m_stdin_fd = fileno(stdin);
            if(::tcgetattr(m_stdin_fd, &m_old_termios) != 0)
               throw System_Error("Getting terminal status failed", errno);

            struct termios noecho_flags = m_old_termios;
            noecho_flags.c_lflag &= ~ECHO;
            noecho_flags.c_lflag |= ECHONL;

            if(::tcsetattr(m_stdin_fd, TCSANOW, &noecho_flags) != 0)
               throw System_Error("Clearing terminal echo bit failed", errno);
            }

         void reenable_echo() override
            {
            if(m_stdin_fd > 0)
               {
               if(::tcsetattr(m_stdin_fd, TCSANOW, &m_old_termios) != 0)
                  throw System_Error("Restoring terminal echo bit failed", errno);
               m_stdin_fd = -1;
               }
            }

         ~POSIX_Echo_Suppression()
            {
            try
               {
               reenable_echo();
               }
            catch(...)
               {
               }
            }

      private:
         int m_stdin_fd;
         struct termios m_old_termios;
      };

   return std::unique_ptr<Echo_Suppression>(new POSIX_Echo_Suppression);

#elif defined(BOTAN_TARGET_OS_HAS_WIN32)

   class Win32_Echo_Suppression : public Echo_Suppression
      {
      public:
         Win32_Echo_Suppression()
            {
            m_input_handle = ::GetStdHandle(STD_INPUT_HANDLE);
            if(::GetConsoleMode(m_input_handle, &m_console_state) == 0)
               throw System_Error("Getting console mode failed", ::GetLastError());

            DWORD new_mode = ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT;
            if(::SetConsoleMode(m_input_handle, new_mode) == 0)
               throw System_Error("Setting console mode failed", ::GetLastError());
            }

         void reenable_echo() override
            {
            if(m_input_handle != INVALID_HANDLE_VALUE)
               {
               if(::SetConsoleMode(m_input_handle, m_console_state) == 0)
                  throw System_Error("Setting console mode failed", ::GetLastError());
               m_input_handle = INVALID_HANDLE_VALUE;
               }
            }

         ~Win32_Echo_Suppression()
            {
            try
               {
               reenable_echo();
               }
            catch(...)
               {
               }
            }

      private:
         HANDLE m_input_handle;
         DWORD m_console_state;
      };

   return std::unique_ptr<Echo_Suppression>(new Win32_Echo_Suppression);

#else

   // Not supported on this platform, return null
   return std::unique_ptr<Echo_Suppression>();
#endif
   }

}
/*
* Various string utils and parsing functions
* (C) 1999-2007,2013,2014,2015,2018 Jack Lloyd
* (C) 2015 Simon Warta (Kullo GmbH)
* (C) 2017 René Korthaus, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <limits>

#if defined(BOTAN_HAS_ASN1)
#endif

namespace Botan {

uint16_t to_uint16(const std::string& str)
   {
   const uint32_t x = to_u32bit(str);

   if(x >> 16)
      throw Invalid_Argument("Integer value exceeds 16 bit range");

   return static_cast<uint16_t>(x);
   }

uint32_t to_u32bit(const std::string& str)
   {
   // std::stoul is not strict enough. Ensure that str is digit only [0-9]*
   for(const char chr : str)
      {
      if(chr < '0' || chr > '9')
         {
         std::string chrAsString(1, chr);
         throw Invalid_Argument("String contains non-digit char: " + chrAsString);
         }
      }

   const unsigned long int x = std::stoul(str);

   if(sizeof(unsigned long int) > 4)
      {
      // x might be uint64
      if (x > std::numeric_limits<uint32_t>::max())
         {
         throw Invalid_Argument("Integer value of " + str + " exceeds 32 bit range");
         }
      }

   return static_cast<uint32_t>(x);
   }

/*
* Convert a string into a time duration
*/
uint32_t timespec_to_u32bit(const std::string& timespec)
   {
   if(timespec.empty())
      return 0;

   const char suffix = timespec[timespec.size()-1];
   std::string value = timespec.substr(0, timespec.size()-1);

   uint32_t scale = 1;

   if(Charset::is_digit(suffix))
      value += suffix;
   else if(suffix == 's')
      scale = 1;
   else if(suffix == 'm')
      scale = 60;
   else if(suffix == 'h')
      scale = 60 * 60;
   else if(suffix == 'd')
      scale = 24 * 60 * 60;
   else if(suffix == 'y')
      scale = 365 * 24 * 60 * 60;
   else
      throw Decoding_Error("timespec_to_u32bit: Bad input " + timespec);

   return scale * to_u32bit(value);
   }

/*
* Parse a SCAN-style algorithm name
*/
std::vector<std::string> parse_algorithm_name(const std::string& namex)
   {
   if(namex.find('(') == std::string::npos &&
      namex.find(')') == std::string::npos)
      return std::vector<std::string>(1, namex);

   std::string name = namex, substring;
   std::vector<std::string> elems;
   size_t level = 0;

   elems.push_back(name.substr(0, name.find('(')));
   name = name.substr(name.find('('));

   for(auto i = name.begin(); i != name.end(); ++i)
      {
      char c = *i;

      if(c == '(')
         ++level;
      if(c == ')')
         {
         if(level == 1 && i == name.end() - 1)
            {
            if(elems.size() == 1)
               elems.push_back(substring.substr(1));
            else
               elems.push_back(substring);
            return elems;
            }

         if(level == 0 || (level == 1 && i != name.end() - 1))
            throw Invalid_Algorithm_Name(namex);
         --level;
         }

      if(c == ',' && level == 1)
         {
         if(elems.size() == 1)
            elems.push_back(substring.substr(1));
         else
            elems.push_back(substring);
         substring.clear();
         }
      else
         substring += c;
      }

   if(!substring.empty())
      throw Invalid_Algorithm_Name(namex);

   return elems;
   }

std::vector<std::string> split_on(const std::string& str, char delim)
   {
   return split_on_pred(str, [delim](char c) { return c == delim; });
   }

std::vector<std::string> split_on_pred(const std::string& str,
                                       std::function<bool (char)> pred)
   {
   std::vector<std::string> elems;
   if(str.empty()) return elems;

   std::string substr;
   for(auto i = str.begin(); i != str.end(); ++i)
      {
      if(pred(*i))
         {
         if(!substr.empty())
            elems.push_back(substr);
         substr.clear();
         }
      else
         substr += *i;
      }

   if(substr.empty())
      throw Invalid_Argument("Unable to split string: " + str);
   elems.push_back(substr);

   return elems;
   }

/*
* Join a string
*/
std::string string_join(const std::vector<std::string>& strs, char delim)
   {
   std::string out = "";

   for(size_t i = 0; i != strs.size(); ++i)
      {
      if(i != 0)
         out += delim;
      out += strs[i];
      }

   return out;
   }

/*
* Parse an ASN.1 OID string
*/
std::vector<uint32_t> parse_asn1_oid(const std::string& oid)
   {
#if defined(BOTAN_HAS_ASN1)
   return OID(oid).get_components();
#else
   throw Not_Implemented("ASN1 support not available");
#endif
   }

/*
* X.500 String Comparison
*/
bool x500_name_cmp(const std::string& name1, const std::string& name2)
   {
   auto p1 = name1.begin();
   auto p2 = name2.begin();

   while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
   while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

   while(p1 != name1.end() && p2 != name2.end())
      {
      if(Charset::is_space(*p1))
         {
         if(!Charset::is_space(*p2))
            return false;

         while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
         while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

         if(p1 == name1.end() && p2 == name2.end())
            return true;
         if(p1 == name1.end() || p2 == name2.end())
            return false;
         }

      if(!Charset::caseless_cmp(*p1, *p2))
         return false;
      ++p1;
      ++p2;
      }

   while((p1 != name1.end()) && Charset::is_space(*p1)) ++p1;
   while((p2 != name2.end()) && Charset::is_space(*p2)) ++p2;

   if((p1 != name1.end()) || (p2 != name2.end()))
      return false;
   return true;
   }

/*
* Convert a decimal-dotted string to binary IP
*/
uint32_t string_to_ipv4(const std::string& str)
   {
   std::vector<std::string> parts = split_on(str, '.');

   if(parts.size() != 4)
      throw Decoding_Error("Invalid IP string " + str);

   uint32_t ip = 0;

   for(auto part = parts.begin(); part != parts.end(); ++part)
      {
      uint32_t octet = to_u32bit(*part);

      if(octet > 255)
         throw Decoding_Error("Invalid IP string " + str);

      ip = (ip << 8) | (octet & 0xFF);
      }

   return ip;
   }

/*
* Convert an IP address to decimal-dotted string
*/
std::string ipv4_to_string(uint32_t ip)
   {
   std::string str;

   for(size_t i = 0; i != sizeof(ip); ++i)
      {
      if(i)
         str += ".";
      str += std::to_string(get_byte(i, ip));
      }

   return str;
   }

std::string erase_chars(const std::string& str, const std::set<char>& chars)
   {
   std::string out;

   for(auto c: str)
      if(chars.count(c) == 0)
         out += c;

   return out;
   }

std::string replace_chars(const std::string& str,
                          const std::set<char>& chars,
                          char to_char)
   {
   std::string out = str;

   for(size_t i = 0; i != out.size(); ++i)
      if(chars.count(out[i]))
         out[i] = to_char;

   return out;
   }

std::string replace_char(const std::string& str, char from_char, char to_char)
   {
   std::string out = str;

   for(size_t i = 0; i != out.size(); ++i)
      if(out[i] == from_char)
         out[i] = to_char;

   return out;
   }

namespace {

std::string tolower_string(const std::string& in)
   {
   std::string s = in;
   for(size_t i = 0; i != s.size(); ++i)
      {
      const int cu = static_cast<unsigned char>(s[i]);
      if(std::isalpha(cu))
         s[i] = static_cast<char>(std::tolower(cu));
      }
   return s;
   }

}

bool host_wildcard_match(const std::string& issued_, const std::string& host_)
   {
   const std::string issued = tolower_string(issued_);
   const std::string host = tolower_string(host_);

   if(host.empty() || issued.empty())
      return false;

   /*
   If there are embedded nulls in your issued name
   Well I feel bad for you son
   */
   if(std::count(issued.begin(), issued.end(), char(0)) > 0)
      return false;

   // If more than one wildcard, then issued name is invalid
   const size_t stars = std::count(issued.begin(), issued.end(), '*');
   if(stars > 1)
      return false;

   // '*' is not a valid character in DNS names so should not appear on the host side
   if(std::count(host.begin(), host.end(), '*') != 0)
      return false;

   // Similarly a DNS name can't end in .
   if(host[host.size() - 1] == '.')
      return false;

   // And a host can't have an empty name component, so reject that
   if(host.find("..") != std::string::npos)
      return false;

   // Exact match: accept
   if(issued == host)
      {
      return true;
      }

   /*
   Otherwise it might be a wildcard

   If the issued size is strictly longer than the hostname size it
   couldn't possibly be a match, even if the issued value is a
   wildcard. The only exception is when the wildcard ends up empty
   (eg www.example.com matches www*.example.com)
   */
   if(issued.size() > host.size() + 1)
      {
      return false;
      }

   // If no * at all then not a wildcard, and so not a match
   if(stars != 1)
      {
      return false;
      }

   /*
   Now walk through the issued string, making sure every character
   matches. When we come to the (singular) '*', jump forward in the
   hostname by the corresponding amount. We know exactly how much
   space the wildcard takes because it must be exactly `len(host) -
   len(issued) + 1 chars`.

   We also verify that the '*' comes in the leftmost component, and
   doesn't skip over any '.' in the hostname.
   */
   size_t dots_seen = 0;
   size_t host_idx = 0;

   for(size_t i = 0; i != issued.size(); ++i)
      {
      dots_seen += (issued[i] == '.');

      if(issued[i] == '*')
         {
         // Fail: wildcard can only come in leftmost component
         if(dots_seen > 0)
            {
            return false;
            }

         /*
         Since there is only one * we know the tail of the issued and
         hostname must be an exact match. In this case advance host_idx
         to match.
         */
         const size_t advance = (host.size() - issued.size() + 1);

         if(host_idx + advance > host.size()) // shouldn't happen
            return false;

         // Can't be any intervening .s that we would have skipped
         if(std::count(host.begin() + host_idx,
                       host.begin() + host_idx + advance, '.') != 0)
            return false;

         host_idx += advance;
         }
      else
         {
         if(issued[i] != host[host_idx])
            {
            return false;
            }

         host_idx += 1;
         }
      }

   // Wildcard issued name must have at least 3 components
   if(dots_seen < 2)
      {
      return false;
      }

   return true;
   }

}
/*
* Simple config/test file reader
* (C) 2013,2014,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::string clean_ws(const std::string& s)
   {
   const char* ws = " \t\n";
   auto start = s.find_first_not_of(ws);
   auto end = s.find_last_not_of(ws);

   if(start == std::string::npos)
      return "";

   if(end == std::string::npos)
      return s.substr(start, end);
   else
      return s.substr(start, start + end + 1);
   }

std::map<std::string, std::string> read_cfg(std::istream& is)
   {
   std::map<std::string, std::string> kv;
   size_t line = 0;

   while(is.good())
      {
      std::string s;

      std::getline(is, s);

      ++line;

      if(s.empty() || s[0] == '#')
         continue;

      s = clean_ws(s.substr(0, s.find('#')));

      if(s.empty())
         continue;

      auto eq = s.find("=");

      if(eq == std::string::npos || eq == 0 || eq == s.size() - 1)
         throw Decoding_Error("Bad read_cfg input '" + s + "' on line " + std::to_string(line));

      const std::string key = clean_ws(s.substr(0, eq));
      const std::string val = clean_ws(s.substr(eq + 1, std::string::npos));

      kv[key] = val;
      }

   return kv;
   }

}
/*
* (C) 2018 Ribose Inc
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

std::map<std::string, std::string> read_kv(const std::string& kv)
   {
   std::map<std::string, std::string> m;
   if(kv == "")
      return m;

   std::vector<std::string> parts;

   try
      {
      parts = split_on(kv, ',');
      }
   catch(std::exception&)
      {
      throw Invalid_Argument("Bad KV spec");
      }

   bool escaped = false;
   bool reading_key = true;
   std::string cur_key;
   std::string cur_val;

   for(char c : kv)
      {
      if(c == '\\' && !escaped)
         {
         escaped = true;
         }
      else if(c == ',' && !escaped)
         {
         if(cur_key.empty())
            throw Invalid_Argument("Bad KV spec empty key");

         if(m.find(cur_key) != m.end())
            throw Invalid_Argument("Bad KV spec duplicated key");
         m[cur_key] = cur_val;
         cur_key = "";
         cur_val = "";
         reading_key = true;
         }
      else if(c == '=' && !escaped)
         {
         if(reading_key == false)
            throw Invalid_Argument("Bad KV spec unexpected equals sign");
         reading_key = false;
         }
      else
         {
         if(reading_key)
            cur_key += c;
         else
            cur_val += c;

         if(escaped)
            escaped = false;
         }
      }

   if(!cur_key.empty())
      {
      if(reading_key == false)
         {
         if(m.find(cur_key) != m.end())
            throw Invalid_Argument("Bad KV spec duplicated key");
         m[cur_key] = cur_val;
         }
      else
         throw Invalid_Argument("Bad KV spec incomplete string");
      }

   return m;
   }

}
/*
* (C) 2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

void Timer::start()
   {
   stop();
   m_timer_start = OS::get_system_timestamp_ns();
   m_cpu_cycles_start = OS::get_cpu_cycle_counter();
   }

void Timer::stop()
   {
   if(m_timer_start)
      {
      if(m_cpu_cycles_start != 0)
         {
         const uint64_t cycles_taken = OS::get_cpu_cycle_counter() - m_cpu_cycles_start;
         if(cycles_taken > 0)
            {
            m_cpu_cycles_used += static_cast<size_t>(cycles_taken * m_clock_cycle_ratio);
            }
         }

      const uint64_t now = OS::get_system_timestamp_ns();

      if(now > m_timer_start)
         {
         const uint64_t dur = now - m_timer_start;

         m_time_used += dur;

         if(m_event_count == 0)
            {
            m_min_time = m_max_time = dur;
            }
         else
            {
            m_max_time = std::max(m_max_time, dur);
            m_min_time = std::min(m_min_time, dur);
            }
         }

      m_timer_start = 0;
      ++m_event_count;
      }
   }

bool Timer::operator<(const Timer& other) const
   {
   if(this->doing() != other.doing())
      return (this->doing() < other.doing());

   return (this->get_name() < other.get_name());
   }

std::string Timer::to_string() const
   {
   if(m_custom_msg.size() > 0)
      {
      return m_custom_msg;
      }
   else if(this->buf_size() == 0)
      {
      return result_string_ops();
      }
   else
      {
      return result_string_bps();
      }
   }

std::string Timer::result_string_bps() const
   {
   const size_t MiB = 1024 * 1024;

   const double MiB_total = static_cast<double>(events()) / MiB;
   const double MiB_per_sec = MiB_total / seconds();

   std::ostringstream oss;
   oss << get_name();

   if(!doing().empty())
      {
      oss << " " << doing();
      }

   if(buf_size() > 0)
      {
      oss << " buffer size " << buf_size() << " bytes:";
      }

   if(events() == 0)
      oss << " " << "N/A";
   else
      oss << " " << std::fixed << std::setprecision(3) << MiB_per_sec << " MiB/sec";

   if(cycles_consumed() != 0)
      {
      const double cycles_per_byte = static_cast<double>(cycles_consumed()) / events();
      oss << " " << std::fixed << std::setprecision(2) << cycles_per_byte << " cycles/byte";
      }

   oss << " (" << MiB_total << " MiB in " << milliseconds() << " ms)\n";

   return oss.str();
   }

std::string Timer::result_string_ops() const
   {
   std::ostringstream oss;

   oss << get_name() << " ";

   if(events() == 0)
      {
      oss << "no events\n";
      }
   else
      {
      oss << static_cast<uint64_t>(events_per_second())
          << ' ' << doing() << "/sec; "
          << std::setprecision(2) << std::fixed
          << ms_per_event() << " ms/op";

      if(cycles_consumed() != 0)
         {
         const double cycles_per_op = static_cast<double>(cycles_consumed()) / events();
         const size_t precision = (cycles_per_op < 10000) ? 2 : 0;
         oss << " " << std::fixed << std::setprecision(precision) << cycles_per_op << " cycles/op";
         }

      oss << " (" << events() << " " << (events() == 1 ? "op" : "ops")
          << " in " << milliseconds() << " ms)\n";
      }

   return oss.str();
   }

}
/*
* Version Information
* (C) 1999-2013,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/


namespace Botan {

/*
  These are intentionally compiled rather than inlined, so an
  application running against a shared library can test the true
  version they are running against.
*/

#define QUOTE(name) #name
#define STR(macro) QUOTE(macro)

const char* short_version_cstr()
   {
   return STR(BOTAN_VERSION_MAJOR) "."
          STR(BOTAN_VERSION_MINOR) "."
          STR(BOTAN_VERSION_PATCH);
   }

const char* version_cstr()
   {

   /*
   It is intentional that this string is a compile-time constant;
   it makes it much easier to find in binaries.
   */

   return "Botan " STR(BOTAN_VERSION_MAJOR) "."
                   STR(BOTAN_VERSION_MINOR) "."
                   STR(BOTAN_VERSION_PATCH) " ("
#if defined(BOTAN_UNSAFE_FUZZER_MODE)
                   "UNSAFE FUZZER MODE BUILD "
#endif
                   BOTAN_VERSION_RELEASE_TYPE
#if (BOTAN_VERSION_DATESTAMP != 0)
                   ", dated " STR(BOTAN_VERSION_DATESTAMP)
#endif
                   ", revision " BOTAN_VERSION_VC_REVISION
                   ", distribution " BOTAN_DISTRIBUTION_INFO ")";
   }

#undef STR
#undef QUOTE

/*
* Return the version as a string
*/
std::string version_string()
   {
   return std::string(version_cstr());
   }

std::string short_version_string()
   {
   return std::string(short_version_cstr());
   }

uint32_t version_datestamp() { return BOTAN_VERSION_DATESTAMP; }

/*
* Return parts of the version as integers
*/
uint32_t version_major() { return BOTAN_VERSION_MAJOR; }
uint32_t version_minor() { return BOTAN_VERSION_MINOR; }
uint32_t version_patch() { return BOTAN_VERSION_PATCH; }

std::string runtime_version_check(uint32_t major,
                                  uint32_t minor,
                                  uint32_t patch)
   {
   if(major != version_major() || minor != version_minor() || patch != version_patch())
      {
      std::ostringstream oss;
      oss << "Warning: linked version (" << short_version_string() << ")"
          << " does not match version built against "
          << "(" << major << '.' << minor << '.' << patch << ")\n";
      return oss.str();
      }

   return "";
   }

}
