#include <plcfg_cli/stdafx.h>
#include <plcfg_cli/ProgramOptions.hpp>

namespace ProLoyalty
{
    using namespace std;
    namespace Cfg
    {

        namespace
        {
            constexpr const char *const OPTION_NAME_ORG = "org";
            constexpr const char *const OPTION_NAME_BUNIT = "bunit";
            constexpr const char *const OPTION_NAME_POS = "pos";
        };

        ProgramOptions &ProgramOptions::add_options(po::options_description &desc)
        {
            BaseCls::add_options(desc);
            desc.add_options()
                (OPTION_NAME_ORG, po::value<string>(&org_), "Партнер ПЛ")
                (OPTION_NAME_BUNIT, po::value<string>(&bunit_), "Магазин")
                (OPTION_NAME_POS, po::value<string>(&pos_), "Касса");
            return *this;
        }

        ProgramOptions &ProgramOptions::add_caption_lines(std::string &caption)
        {
            caption += "\nУтилита конфигуратор DWTerm для командной строки";
            return *this;
        }

    }
}