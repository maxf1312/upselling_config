#include <libplcore/stdafx.h>
#include <gtest/gtest.h>
#include <libplcore/settings.hpp>
//#include "gssettings.h"
#include <libplcore/Utils.hpp>



using namespace std;

//-----------------------------------------------------------------------------
int main(int argc, char* argv[])
{
# ifdef _WINDOWS
	_wsetlocale(LC_ALL, L"Russian_Russia.1251");
# else
	setlocale(LC_ALL, "ru_RU.UTF-8");
# endif // _WINDOWS
	testing::InitGoogleTest(&argc, argv);
	int rv = RUN_ALL_TESTS();	
	cin.get();
	return rv;
}
//-----------------------------------------------------------------------------
ostream& print_Settings(ostream& os, ProLoyalty::ISettings& s, int lvl)
{
	string s_prefix(lvl*4, ' ');
	os << s_prefix << "s.size(): " << s.size() << endl;
	for(size_t i = 0, n = s.size(); i < n; ++i)
	{
		ProLoyalty::ISetting& s0 = s.at(i);
		os << s_prefix << i << ": Name: " << s0.Name() << ", Val: " << s0.AsString() << ", FullName: "  << s0.FullName() << endl;
		ProLoyalty::ISettings* p_ssub = s0.AsSettings();
		if( p_ssub )
			print_Settings(os, *p_ssub, lvl + 1);
	}
	return os;
}
//-----------------------------------------------------------------------------
ostream& operator<<(ostream& os, ProLoyalty::ISettings& s)
{
	return print_Settings(os, s, 0);
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_create_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::TestCteateSettings());
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps;
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_clone_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::TestCteateSettings());
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps;
	ISettings::Ptr ps2(ps->clone());
	ASSERT_TRUE(ps2.get() != NULL);
	cout << *ps2;
	ASSERT_TRUE(ps->item("Settings/passw").AsString() == ps2->item("Settings/passw").AsString());
}
//-----------------------------------------------------------------------------
const char* p_xml_str_settings1 = 
	"<?xml version='1.0' encoding='windows-1251'?>"
	"<Settings>"
	"  <Section0><Param01>1</Param01></Section0>"
	"  <Section1><Param11>A5F45BFADC</Param11></Section1>"
	"  <Section3>"
	"	<A1>2B7AC66E4C235488</A1>"
	"	<A2>2573C27947</A2>"
	"  </Section3>"
	"</Settings>";

const char* p_xml_str_settings2 = 
	"<?xml version='1.0' encoding='windows-1251'?>"
	"<Settings>"
	"  <Section0><Param01></Param01><Param02>0</Param02></Section0>"
	"  <Section1><Param11 _enc='1'></Param11></Section1>"
	"  <Section3 _tp='N' _enc_vals='1'/>"
	"</Settings>";

//-----------------------------------------------------------------------------
TEST(Settings, Test_create_xml_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_str_settings1));
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps;
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_load_xml_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_str_settings2));
	ASSERT_TRUE(ps.get() != NULL);
	cout << "Template: " << endl << *ps << endl;
	ISettings::Ptr ps_data(ProLoyalty::CreateSettings(p_xml_str_settings1));
	ASSERT_TRUE(ps_data.get() != NULL);
	cout << "Data: " << endl << *ps_data << endl;
	ps->load(ProLoyalty::SettingsSrcXML, p_xml_str_settings1);
	cout << "Data loaded by template: " << endl << *ps << endl;
	ASSERT_TRUE(ps->item("Section1/Param11").AsString() == "newzs" );
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_clone_loaded_xml_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_str_settings2));
	ASSERT_TRUE(ps.get() != NULL);
	ps->load(ProLoyalty::SettingsSrcXML, p_xml_str_settings1);
	cout << "Loaded by template: " << endl << *ps << endl;
	ASSERT_TRUE(ps->item("Section1/Param11").AsString() == "newzs" );
	
	ISettings::Ptr ps2(ps->clone());
	cout << "Cloned: " << endl << *ps2 << endl;
	ASSERT_TRUE(ps2->item("Section1/Param11").AsString() == "newzs" );
}
//-----------------------------------------------------------------------------
TEST(Settings, DISABLED_Test_param_access_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::TestCteateSettings());
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps << endl;
	cout << "Settings/conn_timeout: " << ps->item("Settings/conn_timeout").AsInt() << endl;
	cout << "Limits/Limit0: " << ps->item("Limits/Limit0").AsString() << endl;
	cout << "Limits/Limit0/defdisc: " << ps->item("Limits/Limit0/defdisc").AsDouble() << endl;
}
//-----------------------------------------------------------------------------
TEST(Settings, DISABLED_Test_loadxml_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(NULL));
	ASSERT_TRUE(ps.get() != NULL);
	ps->load(SettingsSrcXML, "test.xml");
	cout << *ps;
}
//-----------------------------------------------------------------------------
const char* p_xml_templ_wccard = 
	"<?xml version='1.0' encoding='windows-1251'?>"
	"<AppSettings>"
	"  <Settings>"
	"    <soap_url _enc='1'></soap_url>"
	"    <soap_action _enc='1'></soap_action>"
	"    <soap_usr _enc='1'></soap_usr>"
	"    <soap_psw _enc='1'></soap_psw>"
	"    <soap_orgname _enc='1'></soap_orgname>"
	"    <soap_org _enc='1'></soap_org>"
	"    <soap_bunit _enc='1'></soap_bunit>"
	"    <soap_pos _enc='1'></soap_pos>"
	"  </Settings>"
	"  <Articles _tp='N' _enc_vals='1' _enc_keys='1'/>"
	"  <CardLimits _tp='N' _enc_vals='1' _enc_keys='1'/>"
	"  <Meta>"
	"    <nodecrypt_flags>"
	"      <flag1>Settings/soap_bunit</flag1>"
	"      <flag2>Settings/soap_pos</flag2>"
	"    </nodecrypt_flags>"
	"  </Meta>"
	"</AppSettings>";

TEST(Settings, Test_loadini_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_templ_wccard));
	ASSERT_TRUE(ps.get() != NULL);
	ps->load(SettingsSrcIni, "wscardterm.ini");
	cout << *ps;
	ps->save(SettingsSrcIni, "wscardterm.s.ini");
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_savexml_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_templ_wccard));
	ASSERT_TRUE(ps.get() != NULL);
	ps->load(SettingsSrcIni, "wscardterm.ini");
	cout << *ps;
	ps->save(SettingsSrcXML, "test_saved.xml");
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_saveini0_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::TestCteateSettings());
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps;
	ps->encoded(true);
	ps->save(ProLoyalty::SettingsSrcIni, "save_ini0.ini");
}
//-----------------------------------------------------------------------------
const char* p_xml_templ1 = 
	"<?xml version='1.0' encoding='windows-1251'?>"
	"<Settings>"
	"  <Settings><passw _enc='1'></passw></Settings>"
	"</Settings>";

TEST(Settings, Test_saveini1_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_templ1));
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps;
	ps->load(SettingsSrcIni, "save_ini0.ini");	
	ps->encoded(true);
	ps->save(ProLoyalty::SettingsSrcIni, "save_ini1.ini");
}
//-----------------------------------------------------------------------------
	const char* p_xml_templ_wccardterm = 
	"<?xml version='1.0' encoding='windows-1251'?>"
	"<AppSettings>"
	"  <Settings>"
	"    <soap_url _enc='1'></soap_url>"
	"    <soap_action _enc='1'></soap_action>"
	"    <soap_usr _enc='1'></soap_usr>"
	"    <soap_psw _enc='1'></soap_psw>"
	"    <soap_orgname _enc='1'></soap_orgname>"
	"    <soap_org _enc='1'></soap_org>"
	"    <soap_bunit _enc='1'></soap_bunit>"
	"    <soap_pos _enc='1'></soap_pos>"
	"  </Settings>"
	"  <Articles _tp='N' _enc_vals='1' _enc_keys='1'/>"
	"  <CardLimits _tp='N' _enc_vals='1' _enc_keys='1'/>"
	"  <Meta>"
	"    <nodecrypt_flags>"
	"      <flag1>Settings/soap_bunit</flag1>"
	"      <flag2>Settings/soap_pos</flag2>"
	"    </nodecrypt_flags>"
	"  </Meta>"
	"</AppSettings>";
	
	const char* p_xml_def_wccardterm = 
	"<?xml version='1.0' encoding='windows-1251'?>"
	"<AppSettings>"
	"  <Settings>"
	"    <soap_url _enc='0'>http://37.230.152.215:8183/POSProcessing.asmx</soap_url>" 
	"    <soap_action _enc='0'></soap_action>"
	"    <soap_usr _enc='0'>zs\\KassirExpostroy</soap_usr>"
	"    <soap_psw _enc='0'>kassir0100</soap_psw>"
	"    <soap_orgname _enc='0'>newzs</soap_orgname>"
	"    <soap_org _enc='0'>3705</soap_org>"
	"    <soap_bunit _enc='0'>1</soap_bunit>"
	"    <soap_pos _enc='0'>1</soap_pos>"
	"  </Settings>"
	"</AppSettings>";
TEST(Settings, Test_loaddefxml_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_templ_wccardterm));
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps << endl;

	ISettings::Ptr ps_def(ProLoyalty::CreateSettings(NULL));
	ASSERT_TRUE(ps_def.get() != NULL);
	ps_def->load(SettingsSrcXML, p_xml_def_wccardterm);
	cout << *ps_def << endl;
	
	ps->load(SettingsSrcXML, p_xml_def_wccardterm);
	cout << *ps << endl;
	
	ASSERT_TRUE(ps_def->item("Settings/soap_url").AsString() == ps->item("Settings/soap_url").AsString());
}
//-----------------------------------------------------------------------------
TEST(Settings, DISABLED_Test_loadxml_ld_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps;
	try{
		ps.reset(ProLoyalty::CreateSettings(""));
		ps->load(SettingsSrcXML, "test_ld.xml");
	}
	catch(...)
	{
		cout << "Test_loadxml_ld_settings" << endl;
	}
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps;
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_load_sleepxml_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(NULL));
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps << endl;
	
	ps->load(SettingsSrcXML, "seredinas1c.xml");
	cout << *ps << endl;
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_load_sleepxml_utf8_settings)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(NULL));
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps << endl;

	ps->load(SettingsSrcXML, "seredinas1c.xml");
	std::string s_t = ps->item("cheque_template").AsString();
	cout << s_t << endl;

#ifdef _WINDOWS
	std::locale loc_cp1251(".1251");
#else
	std::locale loc_cp1251("ru_RU.CP1251");
#endif // _WINDOWS

	{
		std::ofstream f_cp1251("template_1251.xml");
		f_cp1251.imbue(loc_cp1251);
		f_cp1251 << s_t; 
	}

	std::wifstream f_in("template_1251.xml");
	f_in.imbue(loc_cp1251); 
	
	std::wstring s, s_all;
	while( f_in )
	{
		if( !std::getline(f_in, s) ) break;
		s_all += s; s_all += L'\n';
	}
	
	std::wcout << s_all << std::endl;

#ifdef _WINDOWS
	std::locale loc_cp_out(".866");
#else
	std::locale loc_cp_out("ru_RU.KOI8R");
#endif // _WINDOWS
	
	std::wofstream f_out("template_out.xml");
	if( f_out )
	{
		f_out.imbue(loc_cp_out);
		f_out << s_all; 
	}

}
//-----------------------------------------------------------------------------
// ������� ����������� ����� 1 � ��������� 1 � ���� 2 � ��������� 2
//-----------------------------------------------------------------------------
// ������� ������ wstring � ���� � ��������� �������
bool write_wstr_to_file(const std::wstring& s, const std::string& filename, const std::locale* loc)
{

    std::wofstream f_out(filename.c_str());
	if( !f_out )
	    return false;

    if( loc )
	    f_out.imbue(*loc);

	f_out << s; 

    return f_out.good();
}
//-----------------------------------------------------------------------------
// ������� ������ wstring � ����  � ��������� ���������
bool write_wstr_to_file(const std::wstring& s, const std::string& filename, const std::string& loc_name)
{
    if( !loc_name.empty() )
    {
        std::locale loc_cp_out(loc_name.c_str());
        return write_wstr_to_file(s, filename, &loc_cp_out);
    }
    return write_wstr_to_file(s, filename, NULL);
}
//-----------------------------------------------------------------------------
// ������� ������ wstring �� ����� � ��������� �������
std::wstring read_wstr_from_file(const std::string& filename, const std::locale* loc)
{
    std::wstring s;

    std::wifstream f_in(filename.c_str());
    f_in >> std::noskipws;
    if( loc )
	    f_in.imbue( *loc ); 

    for( wchar_t ch = L'\0'; f_in >> ch ; ch = L'\0' )
	{
        s += ch; 
	}

    return s;
}
//-----------------------------------------------------------------------------
// ������� ������ wstring �� ����� � ��������� ���������
std::wstring read_wstr_from_file(const std::string& filename, const std::string& loc_name)
{
    if( !loc_name.empty() )
    {
        std::locale loc_cp(loc_name.c_str());
        return read_wstr_from_file(filename, &loc_cp);
    }
    return read_wstr_from_file(filename, NULL);
}

//-----------------------------------------------------------------------------
TEST(Settings, Test_load_sleepxml_utf8_settings_symb)
{
	using namespace ProLoyalty;
	ISettings::Ptr ps(ProLoyalty::CreateSettings(NULL));
	ASSERT_TRUE(ps.get() != NULL);
	cout << *ps << endl;

	ps->load(SettingsSrcXML, "seredinas1c.xml");
	std::string s_t = ps->item("cheque_template").AsString();
	cout << s_t << endl;

#ifdef _WINDOWS
	std::locale loc_cp1251(".1251");
#else
	std::locale loc_cp1251("ru_RU.CP1251");
#endif // _WINDOWS

	{
		std::ofstream f_cp1251("template_1251.xml");
		f_cp1251.imbue(loc_cp1251);
		f_cp1251 << s_t; 
	}

   	std::wstring s_all = read_wstr_from_file( 
            "template_1251.xml",
#ifdef _WINDOWS
	        ".1251"
#else
            "ru_RU.CP1251"
#endif // _WINDOWS
        );


	std::wcout << s_all << std::endl;
    bool b = 
        write_wstr_to_file(
            s_all,
            "template_out.xml",
#ifdef _WINDOWS
	        ".866"
#else
	        "ru_RU.KOI8R"
#endif // _WINDOWS
        );

	ASSERT_TRUE( b   );
}
//-----------------------------------------------------------------------------
TEST(Settings, DISABLED_Test_update_settings)
{
	using namespace std;
	using namespace ProLoyalty;
	
	wstring err_msg;

	// TODO check and refactor UpdateProcSettings implementation!
	// bool bRes = UpdateProcSettings(L"http://mobile.seredina.ru/upd/data/V2/", NULL, L"1.0.0.1");
	bool bRes = true;
	ASSERT_EQ(bRes, true);
}
//-----------------------------------------------------------------------------
TEST(Settings, Test_load_bad_settings)
{
	using namespace std;
	using namespace ProLoyalty;

	const char* p_xml_templ_wccardterm = 
	"<?xml version='1.0' encoding='windows-1251'?>"
	"<AppSettings>"
	"  <Settings>"
	"    <last_resolve _enc='1' _tp='S'></last_resolve>"
	"    <last_update _enc='1' _tp='S'></last_update>"
	"  </Settings>"
	"  <DNS _tp='N' _enc_vals='1' _enc_keys='1'/>"
	"</AppSettings>";
	
	std::string s_path = path_from_utf16(get_config_dir() + L"bad_ini.ini"), 
				nm = "DNS/mobile.seredina.ru";
	ISettings::Ptr ps(ProLoyalty::CreateSettings(p_xml_templ_wccardterm));

	try
	{
		ps->encoded(true);
		ps->load(SettingsSrcIni, s_path.c_str());
	}
	catch( ProLoyalty::SettingsError& err )
	{
		cout << "CachedIPv4Resolver::init error: " <<  err.what() << std::endl;
	}

	ASSERT_TRUE(ps.get() != NULL);
	
	unsigned	v = 0;
	time_t		tt_now = time(NULL);
		
	try
	{
		time_t tt = ps->item("Settings/last_resolve").AsUInt();
		v = ps->item(nm.c_str()).AsUInt();
		cout << "tt: " << tt << ", v: " << v << endl;
	}
	catch( ProLoyalty::SettingNotFound& err)
	{
		cout << "SettingNotFound error: " <<  err.what() << std::endl;
		v = 0;
	}

	if( 0 == v )
	{ 
		v = 0x80000000;
		if( ps.get())
		{
			char ip_str[32];
			sprintf(ip_str, "%0X", v);
			cout << ip_str << std::endl;

			try
			{
				ps->item_add("Settings/last_resolve", true).FromUInt((unsigned)tt_now);
				ps->item_add(nm.c_str(), true).FromUInt(v);
				ps->save(SettingsSrcIni, s_path.c_str());
			}
			catch( ProLoyalty::SettingNotFound& err)
			{
				cout << "saving resolv params err: " << err.what() << std::endl;
			}			
		}
	}	
}
//-----------------------------------------------------------------------------
