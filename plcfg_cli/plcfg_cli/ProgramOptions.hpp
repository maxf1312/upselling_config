#pragma once

#include <plcfg_cli/stdafx.h>
#include <libplcore/ProgramOptions.hpp>

namespace ProLoyalty
{
	namespace Cfg
	{
	/// @brief Опции командной строки - ключи для настроек 
	struct ProgramOptions : ProLoyalty::ProgramOptions
	{
		using BaseCls = ProLoyalty::ProgramOptions;
        std::string org_, bunit_, pos_;
		ProgramOptions() = default;
		ProgramOptions(std::istream *istrm, std::ostream *ostrm) : BaseCls(istrm, ostrm) {}
		virtual ProgramOptions &add_options(po::options_description &desc) override;
		virtual ProgramOptions &add_caption_lines(std::string &caption) override;
	};

	}

}
