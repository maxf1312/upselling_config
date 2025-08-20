#pragma once

#include <libplcore/plcorexp.h>

namespace ProLoyalty{
	/// @brief  Интерфейс для зашифровки/расшифровки строк
	struct PLCORE_API IStringCrypter
	{
		using Ptr_t = std::unique_ptr<IStringCrypter>;
		virtual ~IStringCrypter() {}
		virtual IStringCrypter* clone() const = 0;
		virtual std::string encrypt_string(const char* s) = 0;
		virtual std::string decrypt_string(const char* s) = 0;

		static Ptr_t  Create(const char* crypter_name);
	};

}
