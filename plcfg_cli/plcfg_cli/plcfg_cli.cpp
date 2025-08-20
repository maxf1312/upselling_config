#include <plcfg_cli/stdafx.h>
#include <plcfg_cli/ProgramOptions.hpp>
#include <libplcore/settings.hpp>


using namespace std;
using namespace ProLoyalty;

int main(int argc, const char* argv[])
{
	try
	{
		Cfg::ProgramOptions options;
		if (!options.parse_command_line(argc, argv) || options.need_help_)
        {
		    if(options.need_help_)
                std::cout << options.help_;
        	return 1;
		}

	}	
	catch(const std::exception &e)
	{
		std::cerr << e.what() << std::endl;
	}
    return 0;
}
