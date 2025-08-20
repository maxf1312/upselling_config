#pragma once

#include <plcrypt/stdafx.h>
#include <libplcore/ProgramOptions.hpp>

namespace ProLoyalty
{

	namespace Crypto
	{
    /// @brief Опции командной строки для утилиты
	struct ProgramOptions : ProLoyalty::ProgramOptions
	{
        using BaseCls = ProLoyalty::ProgramOptions;
		ProgramOptions(std::istream *istrm, std::ostream *ostrm) : BaseCls(istrm, ostrm) {}
	};

	}

}
