#include <libplcore/stdafx.h>
#include <libplcore/ProgramOptions.hpp>

namespace ProLoyalty{
    using namespace std;
    namespace po = boost::program_options;
   
    std::string help_to_str(po::options_description const& desc)
    {
        std::ostringstream oss;
        oss  << desc << std::endl;
        return oss.str();
    }

    namespace {
        constexpr const char* const OPTION_NAME_HELP = "help"; 
        constexpr const char* const OPTION_NAME_DECRYPT = "decrypt"; 
        constexpr const char* const OPTION_NAME_HELP_SH = "h"; 
        constexpr const char* const OPTION_NAME_DECRYPT_SH = "d"; 
    };

    ProgramOptions& ProgramOptions::add_options(po::options_description& desc)
    {
        desc.add_options()
            ((OPTION_NAME_HELP + std::string(",") + OPTION_NAME_HELP_SH).c_str(), po::bool_switch(&need_help_), "Отображение справки")
            ((OPTION_NAME_DECRYPT + std::string(",") + OPTION_NAME_DECRYPT_SH).c_str(), po::bool_switch(&decrypt_), "Дешифрование (по умолчанию - шифрование)");

        return *this;
    }

    ProgramOptions& ProgramOptions::add_positional(po::positional_options_description& pos_desc)
    {
        return *this;
    }

    ProgramOptions& ProgramOptions::add_caption_lines( std::string& caption )
    {
        caption = "Аргументы командной строки";
        return *this;
    }

    bool ProgramOptions::parse_command_line(int argc, const char* argv[])
    {
        *this = ProgramOptions();
        ProgramOptions& parsed_options = *this;
        
        std::string caption;
        add_caption_lines( caption );
        po::options_description desc(caption);
        po::positional_options_description pos_desc;
        add_options(desc).add_positional(pos_desc);

        po::variables_map vm;
        po::store(po::command_line_parser(argc, argv).options(desc).positional(pos_desc).run(), vm);
        po::notify(vm);

        bool not_need_exit = true;
        if( parsed_options.need_help_ )
            parsed_options.help_ = help_to_str(desc), not_need_exit = false;
        
        return not_need_exit;
    }
};