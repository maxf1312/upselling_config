#include <libplcore/botan_all.h>

#include <libplcore/crypto.hpp>
#include <libplcore/ofb_ctr.hpp>
#include <libplcore/Utils.hpp>

using namespace Botan;
namespace ProLoyalty{

	class EmptyStringCrypter : public IStringCrypter
	{
	public:
		virtual IStringCrypter* clone() const { return new EmptyStringCrypter(*this); }
		virtual std::string encrypt_string(const char* s){ return s; }
		virtual std::string decrypt_string(const char* s){ return s; }
	};

	class IDEAStringCrypter : public IStringCrypter
	{
	public:
				IDEAStringCrypter(byte aKey[16]);
		virtual IStringCrypter* clone() const { return new IDEAStringCrypter(*this); }
		virtual std::string encrypt_string(const char* s);
		virtual std::string decrypt_string(const char* s);
	private: 
        Keyed_Filter*	create_cipher();
		byte m_Key[16];

	};
	//--------------------------------------------------------------------------------------
	IDEAStringCrypter::IDEAStringCrypter(byte aKey[16])
	{
		std::copy(aKey, aKey + 16, m_Key);
	}
	//--------------------------------------------------------------------------------------
	Keyed_Filter* IDEAStringCrypter::create_cipher()
	{
		SymmetricKey		 key(m_Key, 16);
		InitializationVector iv(m_Key, 8);
	
		std::unique_ptr<BlockCipher> block_cipher = BlockCipher::create("IDEA");
		Keyed_Filter* filt = new StreamCipher_Filter(new OFB_CTR_BE(block_cipher->clone()));
		filt->set_key(key);
		filt->set_iv(iv);
		return filt;
	}
	//--------------------------------------------------------------------------------------
	std::string IDEAStringCrypter::encrypt_string(const char* s)
	{
		if( !s || !*s ) return "";
		
		Keyed_Filter* filt = create_cipher();
		Pipe pipe(filt, new Hex_Encoder);
	
		pipe.start_msg();
		pipe.write(s ? s : "");
		pipe.end_msg();

		return pipe.read_all_as_string(0);
	}
	//--------------------------------------------------------------------------------------
	std::string IDEAStringCrypter::decrypt_string(const char* s)
	{
		if( s && *s )
			try
			{
				Keyed_Filter* filt = create_cipher();
				Pipe pipe(new Hex_Decoder, filt);

				pipe.start_msg();
				pipe.write(s ? s : "");
				pipe.end_msg();

				return pipe.read_all_as_string(0);		
			}
			catch(std::invalid_argument const&)
			{
				;
			}
		return !s || !*s ? "" : s;
	}
	//--------------------------------------------------------------------------------------
	IStringCrypter::Ptr_t  IStringCrypter::Create(const char* crypter_name)
	{
		if( !crypter_name ) crypter_name = "";
		Ptr_t  crypter(new EmptyStringCrypter);
		if( is_string_equals_ci(crypter_name, "base_crypter") )
		{
			byte aKey[16] = {0x1F, 0x2F, 0xCA, 0xFC, 0x16, 0x29, 0x3F, 0x22, 0xF8, 0xD1, 0x1D, 0x42, 0x17, 0x15, 0xDC, 0xF1};
			crypter.reset(new IDEAStringCrypter(aKey));
		}
		return crypter;
	}
	//--------------------------------------------------------------------------------------
}
