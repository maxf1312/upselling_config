#pragma once

#include <libplcore/stdafx.h>
#include <boost/program_options.hpp>

namespace ProLoyalty
{
	namespace po = boost::program_options;

	/// @brief Опции командной строки - базовый, только минимум ключей 
	struct ProgramOptions
	{
		std::string infile_nm_, outfile_nm_;
		std::string key_;
		std::string help_;
		bool need_help_;
		bool decrypt_;
		std::istream *is_;
		std::ostream *os_;
		ProgramOptions() : need_help_(false), decrypt_(false), is_(nullptr), os_(nullptr) {}
		ProgramOptions(std::istream *istrm, std::ostream *ostrm) : need_help_(false), decrypt_(false), is_(istrm), os_(ostrm) {}
		virtual bool parse_command_line(int argc, const char *argv[]);
		virtual ProgramOptions &add_options(po::options_description &desc);
		virtual ProgramOptions &add_positional(po::positional_options_description &pos_desc);
		virtual ProgramOptions &add_caption_lines(std::string &caption);
	};

	namespace Crypto
	{

	}

}
