#include <plcrypt/stdafx.h>
#include <plcrypt/ProgramOptions.hpp>
#include <libplcore/crypto.hpp>

using namespace std;
using namespace ProLoyalty;
int main(int argc, const char* argv[])
{
	try
	{
		ProgramOptions options;
		if (!options.parse_command_line(argc, argv) || options.need_help_)
        {
		    if(options.need_help_)
                std::cout << options.help_;
        	return 1;
		}

        auto p_crypter = IStringCrypter::Create("base_crypter");
        string inp_s; 
        while( getline(cin, inp_s) )
        {
            auto out_s = options.decrypt_ ? p_crypter->decrypt_string(inp_s.c_str()) 
                                          : p_crypter->encrypt_string(inp_s.c_str());
            cout << out_s << std::endl;
        }
	}	
	catch(const std::exception &e)
	{
		std::cerr << e.what() << std::endl;
	}
    return 0;
}