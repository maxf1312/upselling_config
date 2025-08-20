#include <libplcore/stdafx.h>

#ifdef _WINDOWS
#	include <windows.h>
#	include <Shellapi.h>
#	include <shlwapi.h>
#	include <shlobj.h>
#	include <io.h>
#else
#	include <sys/stat.h>
#	include <errno.h>
#	include <unistd.h>
#	include <fnmatch.h>
#endif // _WINDOWS

#include <cstdlib>
#include <cassert>
#include <cstdarg>
#include <cerrno>
#include <cstring>
#include <cctype>
#include <string>
#include <sstream>
#include <locale>
#include <array>

#include <libplcore/Utils.hpp>
#include <libplcore/UtilsDate.hpp>
#include <libplcore/plposprocdefs.h>
//#include <libplcore/gsreqresp.h>
//#include <libplcore/logger.h>
#include <libplcore/rounding-algorithms.hpp>

namespace ProLoyalty{

	using namespace std;

	const string s_BrandDir {"Seredina"};

const char * const trim_delimiters_t<char>::value = " \t\r\n";  
const wchar_t * const trim_delimiters_t<wchar_t>::value = L" \t\r\n";  

const char      quote_char_t<char>::value = '\"';
const wchar_t   quote_char_t<wchar_t>::value = L'\"';  


//cpDEF
//-----------------------------------------------------------------------------
// UTF16 -> UTF8 conversion
std::string toUTF8( const std::wstring &input, unsigned cp /*= CP_UTF8*/  )
{
    // get length
# ifdef _WINDOWS
    size_t length = WideCharToMultiByte( cp, NULL,
					input.c_str(),
					static_cast<int>(input.size()),
					NULL, 0,
					NULL, NULL );
# else
    size_t length = wcstombs (NULL, input.c_str(), input.size());
# endif //_WINDOWS

    std::string result;
    if( static_cast<size_t>(-1) != length && length > 0 )
    {
		std::vector<std::string::value_type> res_buf(length + 1);
# ifdef _WINDOWS
        if( !WideCharToMultiByte( cp, NULL,
                                  input.c_str(),
				  static_cast<int>(input.size()),
                                  &res_buf[0],
				  static_cast<int>(res_buf.size()),
                                  NULL, NULL ) )
# else
        size_t cvt_len = wcstombs (&res_buf[0], input.c_str(), length + 1); 
	if( static_cast<size_t>(-1) == cvt_len )
# endif //_WINDOWS
	{
		throw std::runtime_error( "Failure to execute toUTF8: conversion failed." );
	}
	result.resize(length + 1);
	std::copy(res_buf.begin(), res_buf.end(), result.begin());
	result.resize(length);
    }
    return result;
}
//-----------------------------------------------------------------------------
// UTF8 -> UTF16 conversion
std::wstring toUTF16( const std::string &input, unsigned cp /*= CP_UTF8*/ )
{
    // get length
    std::wstring result;
# ifdef _WINDOWS 
	size_t length = MultiByteToWideChar( cp, NULL,
					     input.c_str(),
					     static_cast<int>(input.size()),
                                             NULL, 0 );
# else
    size_t length = mbstowcs(NULL, input.c_str(), input.size());
# endif //_WINDOWS
    if( static_cast<size_t>(-1) != length && length > 0 )
    {
	std::vector<std::wstring::value_type> res_buf(length + 1);
# ifdef _WINDOWS
        if( !MultiByteToWideChar(cp, NULL,
                                 input.c_str(), static_cast<int>(input.size()),
                                 &res_buf[0], static_cast<int>(res_buf.size())) )
# else
        if( static_cast<size_t>(-1) == mbstowcs(&res_buf[0], input.c_str(), input.size()) )
# endif //_WINDOWS
	{
		throw std::runtime_error( "Failure to execute toUTF16: conversion failed." );
	}
	result.resize(length + 1);
	std::copy(res_buf.begin(), res_buf.end(), result.begin());
	result.resize(length);
    }
    return result;
}
//-----------------------------------------------------------------------------
// UTF8 -> UTF16 conversion with locale name
LocaleSetter::LocaleSetter(int categ, const char* loc_nm) : m_categ(categ), m_prev_loc("")
{
    m_prev_loc = setlocale(categ, loc_nm);
    if (!m_prev_loc)
        throw std::runtime_error(error_string(errno));
}
	
LocaleSetter::~LocaleSetter()
{
    if (m_prev_loc)
        setlocale(m_categ, m_prev_loc);
}


namespace {
	inline size_t	wrap_mbstowcs(wchar_t* _Dest, size_t sizeInWords, char const* _Source, size_t _MaxCount)
	{
#ifdef _WINDOWS
		size_t length = 0;
		sizeInWords = _Dest ? 0 : sizeInWords;
		errno_t errcd = mbstowcs_s(&length, _Dest, sizeInWords, _Source, _MaxCount);
		return errcd ? (std::numeric_limits<size_t>::max)() : length;
#else
		return mbstowcs(_Dest, _Source, _MaxCount);
#endif
	}
}

std::wstring toUTF16( const std::string &input, const char* locale_nm )
{
    LocaleSetter _loc(LC_CTYPE, locale_nm);

	std::wstring result;
    // get length
	size_t length = wrap_mbstowcs(nullptr, 0, input.c_str(), input.size());
    if( static_cast<size_t>(-1) != length && length > 0 )
    {
	std::vector<std::wstring::value_type> res_buf(length + 1);
        if( static_cast<size_t>(-1) == wrap_mbstowcs(&res_buf[0], res_buf.size(), input.c_str(), input.size()) )
	{
		throw std::runtime_error( "Failure to execute toUTF16: conversion failed." );
	}
	result.resize(length + 1);
	std::copy(res_buf.begin(), res_buf.end(), result.begin());
	result.resize(length);
    }
    return result;
}
//-----------------------------------------------------------------------------
id_transaction_t  id_transaction_t_from_string(const std::string& s)
{
	id_transaction_t  r = 0;	
	std::istringstream iss(s);
	iss >> r;
	return r;
}
//-----------------------------------------------------------------------------
std::string		  id_transaction_t_to_string(const id_transaction_t& t)
{
	std::ostringstream oss;
	oss << t;
	return oss.str();
}
//-----------------------------------------------------------------------------
id_transaction_t  id_transaction_t_from_wstring(const std::wstring& s)
{
	id_transaction_t  r = 0;	
	std::wistringstream iss(s);
	iss >> r;
	return r;
}
//-----------------------------------------------------------------------------
std::wstring	  id_transaction_t_to_wstring(const id_transaction_t& t)
{
	std::wostringstream oss;
	oss << t;
	return oss.str();
}
//-----------------------------------------------------------------------------
/// Разбирает строку с ИД процессинга. 
/// Строка хранит данные в формате: 
/// [IDProcessor[|PathToIni[|Decode:{0,1}]]] 
/// IDProcessor - Идентификатор процессора, в формате NSpace:Processor, 
///				  по умолчанию равен "ZS:ProcessorV2".	
/// PathToIni   - Путь к файлу настроек, если указан не абсолютный путь, 
///				  производится его нормализация и приведение к абсолютному пути.
///				  Если не указан - считается путь к ИНИ по умолчанию (wscardterm.ini)	
/// Decode		- Флаг декодирования, по умолчанию равен 0. Если равен 1, параметры 
///				  из файла дешифруются.
/// @param [in]  processing_id - строка c полным ID
/// @param [out] processor_id - ИД процессора, например "ZS:ProcessorV2"
/// @param [out] path_to_ini - путь к ИНИ, в конце после знака | может быть список параметров
///				 "/usr/local/seredina/wscardterm.ini|Decode:1" 
//-----------------------------------------------------------------------------
void parse_proc_id(const wchar_t* processing_id, std::wstring& processor_id, std::wstring& path_to_ini)
{
	processor_id.clear();
	path_to_ini.clear();
	if( !processing_id ) processing_id = L"";
	
	wchar_t const* pwc = wcschr(processing_id, L'|');
	if( !pwc ) pwc = processing_id + wcslen(processing_id);
	
	processor_id.append(processing_id, pwc);
	if( !processor_id.length() ) processor_id = L"ZS:ProcessorV2";
	
	if( L'|' == *pwc ) ++pwc, path_to_ini.append(pwc, pwc + wcslen(pwc));
}

//-----------------------------------------------------------------------------
/// @init_response_result_t - inits response buffer
//-----------------------------------------------------------------------------
void init_response_result_t(seredina_response_t& resp)
{
	init_struct_t(resp);
	init_struct_t(resp.base_result, true);
}
//-----------------------------------------------------------------------------
std::string get_home_dir_impl(const char* sub_dir)
{
	if( !sub_dir ) sub_dir = "";
#ifdef _WINDOWS
	vector<string::value_type> vDir(MAX_PATH);
	HRESULT hr = SHGetFolderPathA(0, CSIDL_COMMON_DOCUMENTS, 0, 0, &vDir[0]);
	if( FAILED(hr) )
	{
		ostringstream s;
		s << "Ошибка получения директории: " << hr;
		throw std::runtime_error(s.str());
	}

	string sDir(&vDir[0]);

#ifndef _DEBUG_RUS_CFG_DIR
	sDir += "\\" + s_BrandDir + "\\";
#else	
	sDir += "\\Золотая Середина\\";
#endif

	sDir += sub_dir;

	if( sDir[sDir.length() -  1] != '\\' )
		sDir += '\\'; 

	if( !PathFileExistsA(sDir.c_str()) && ERROR_SUCCESS != SHCreateDirectoryExA(NULL, sDir.c_str(), NULL) )
	{
		ostringstream s;
		s << "Невозможно создать директорию " << sDir;
		throw std::runtime_error(s.str());
	}
	return sDir;
#else
	// /home/ufo/.UFO/tmp
	bool b_append = true;
	string sDir = "/home/ufo/.UFO/tmp";
	if( 0 == strcmp(sub_dir, "log") )
		sDir = "/var/log/seredina", b_append = false;
	
	if( 0 == strcmp(sub_dir, "db") )
		sDir = "/var/db/seredina", b_append = false;
	
	mkdir(sDir.c_str(), 0755);
	if(b_append)
	{
		sDir += "/"; sDir += sub_dir;
		mkdir(sDir.c_str(), 0755);
	}
	if( sDir[sDir.length() -  1] != '/' )
		sDir += '/'; 
	return sDir;
#endif
}
//-----------------------------------------------------------------------------
std::wstring get_home_dir(const wchar_t* sub_dir)
{
	return path_to_utf16(get_home_dir_impl(path_from_utf16(sub_dir).c_str()).c_str());
}
//-----------------------------------------------------------------------------
std::string get_bin_dir_impl()
{
#ifdef _WINDOWS
	vector<string::value_type> vDir(MAX_PATH);
    HRESULT hr = SHGetFolderPathA(0, CSIDL_PROGRAM_FILES, 0, 0, &vDir[0]);
	if( FAILED(hr) )
	{
		ostringstream s;
		s << "Ошибка получения bin-директории: " << hr;
		throw std::runtime_error(s.str());
	}

	string sDir(&vDir[0]);

#ifndef _DEBUG_RUS_CFG_DIR
	sDir += "\\Seredina\\";
#else	
	sDir += "\\Золотая Середина\\";
#endif

	sDir += "wscardterm\\";

	if( sDir[sDir.length() -  1] != '\\' )
		sDir += '\\'; 

	return sDir;
#else
	string sDir = "/usr/local/lib";
	if( sDir[sDir.length() -  1] != '/' )
		sDir += '/'; 
	return sDir;
#endif
}
//-----------------------------------------------------------------------------
std::wstring get_bin_dir()
{
	return path_to_utf16(get_bin_dir_impl());
}
//-----------------------------------------------------------------------------
std::wstring get_config_dir()
{
	const wchar_t* sub_dir = L"";
#ifndef _WINDOWS
	sub_dir = L"../config";
#endif
	return get_home_dir(sub_dir);
}
//-----------------------------------------------------------------------------
std::wstring get_log_dir()
{
	const wchar_t* sub_dir = L"Logs";
#ifndef _WINDOWS
	sub_dir = L"logs";
#endif
	return get_home_dir(sub_dir);
}
//-----------------------------------------------------------------------------
std::wstring get_log_nm(const wchar_t* suffix)
{
	std::wstring fn = format_time_t(time(NULL), L"%Y%m%d", true);
	if( suffix && *suffix )	fn += L"_", fn += suffix;
	fn += L".log";
	return fn;
}
//-----------------------------------------------------------------------------
std::wstring get_log_path(const wchar_t* suffix)
{
	return get_log_dir() + get_log_nm(suffix);
}
//-----------------------------------------------------------------------------
std::wstring get_db_dir()
{
	const wchar_t* sub_dir = L"";
#ifndef _WINDOWS
	sub_dir = L"gold";
#endif
	return get_home_dir(sub_dir);
}
//-----------------------------------------------------------------------------
std::wstring get_tmp_dir()
{
	const wchar_t* sub_dir = L"";
#ifdef _WINDOWS
	sub_dir = L"tmp";
#endif
	return get_home_dir(sub_dir);
}
//-----------------------------------------------------------------------------
std::wstring get_lib_dir() 
{
#ifdef _WINDOWS
	vector<string::value_type> vDir(MAX_PATH);
	HRESULT hr = SHGetFolderPathA(0, CSIDL_PROGRAM_FILES, 0, 0, &vDir[0]);
	if (FAILED(hr))
	{
		ostringstream s;
		s << "Ошибка получения директории: " << hr;
		throw std::runtime_error(s.str());
	}

	string sDir(&vDir[0]);

#ifndef _DEBUG_RUS_CFG_DIR
	sDir += "\\" + s_BrandDir + "\\wscardterm\\";
#else	
	sDir += "\\Золотая Середина\\";
#endif

	if (sDir[sDir.length() - 1] != '\\')
		sDir += '\\';

	if (!PathFileExistsA(sDir.c_str()) && ERROR_SUCCESS != SHCreateDirectoryExA(NULL, sDir.c_str(), NULL))
	{
		ostringstream s;
		s << "Невозможно создать директорию " << sDir;
		throw std::runtime_error(s.str());
	}
	return path_to_utf16(sDir);
#else
	return {};
#endif
}
//-----------------------------------------------------------------------------
std::string  path_from_utf16(const wchar_t* path)
{
    typedef codecvt<wchar_t, char, mbstate_t> Cvt_facet;
    
    if( !path || !*path ) return "";

	char* sLoc = setlocale(LC_CTYPE, NULL);
	if( !sLoc || *sLoc == 'C' )
		setlocale(LC_CTYPE, "");

	const size_t max_path = 520;
	
    locale loc("");
    Cvt_facet const& cnv = use_facet<Cvt_facet>(loc);
	mbstate_t stat = mbstate_t();
	char* to_next;
	const wchar_t* from_next_w;
	size_t path_len = wcslen(path);
	
	vector<string::value_type> res_buf(max_path + 1);
	Cvt_facet::result res = cnv.out(stat, path, path + path_len, from_next_w, &res_buf[0], &res_buf[max_path], to_next); 
	    
    if (Cvt_facet::ok != res)
        throw std::runtime_error("Cannot convert path from UTF16 to current OS locale, error: " + to_string(res));

    string result(&res_buf[0], to_next - &res_buf[0]);
	return result;
}
//-----------------------------------------------------------------------------
std::string  path_from_utf16(const std::wstring& path)
{
	return  path_from_utf16(path.c_str());
}
//-----------------------------------------------------------------------------
std::wstring path_to_utf16(const char* path)
{
	return path ? toUTF16(path, cpACP) : L"";
}
//-----------------------------------------------------------------------------
std::wstring path_to_utf16(const string& path)
{
	return path_to_utf16(path.c_str());
}

//-----------------------------------------------------------------------------
/// @normalize_file_nm Нормализует имя файла из относительного в абсолютное.  
/// @param [in]  fn - имя файла, если NULL - значит имя wscardterm.ini.
//  Алгоритм таков, что сначала ищем файл в текущем каталоге, 
//  затем в каталоге с процессом, и затем только в домашнем.   
// TODO - нормальная реализация
//-----------------------------------------------------------------------------
std::wstring normalize_file_nm(const wchar_t* fn)
{	
	if (!fn || L'\0' == *fn) fn = L"wscardterm.ini";
	
	wstring wpath = fn;
	string  path = path_from_utf16(fn);
	
	if( 0 != is_file_access(path, 0)  )
	{
		wpath = get_config_dir();
		wpath += fn;
	}
	return wpath;
}
//-----------------------------------------------------------------------------
/// @normalize_ini_file_nm Нормализует имя файла настройки из относительного
/// в абсолютное, учитывая возможность значения по умолчанию.
/// @param [in]  ini_file - имя файла, если NULL - значит имя wscardterm.ini.
/// @param [in]  needed_ext - требуемое(ожидаемое) расширение, начинается с '.'
//-----------------------------------------------------------------------------
std::wstring normalize_ini_file_nm(const wchar_t* ini_file, const wchar_t* needed_ext)
{
	wstring ws_ini_file = ini_file && *ini_file ? ini_file : L"wscardterm.ini";
	if( needed_ext && *needed_ext )
	{
		wstring::size_type i = ws_ini_file.rfind(L'.');
		if( wstring::npos == i )
		{
			ws_ini_file += needed_ext;
		}
		else if( wstring::npos == ws_ini_file.rfind(needed_ext) )
		{
			ws_ini_file.erase(i);
			ws_ini_file += needed_ext;
		}
	}
	return normalize_file_nm(ws_ini_file.c_str());
}
//-----------------------------------------------------------------------------
std::string		str_to_upper  (std::string  const& s)
{
    std::string rv;
    std::transform(s.begin(), s.end(), std::back_inserter(rv), [](const char ch){ return std::toupper(ch); } );
    return rv;
}
//-----------------------------------------------------------------------------
std::wstring	wstr_to_upper (std::wstring const& s)
{
    std::wstring rv;
    std::transform(s.begin(), s.end(), std::back_inserter(rv), towupper);
    return rv;
}
//-----------------------------------------------------------------------------
string& str_trim(string& s, const char* szDelims)
{
  s.erase(0, s.find_first_not_of( szDelims ) );
  s.erase(s.find_last_not_of( szDelims ) + 1);
  return s;
}
//-----------------------------------------------------------------------------
wstring& wstr_trim(wstring& s, const wchar_t* szDelims)
{
  s.erase(0, s.find_first_not_of( szDelims ) );
  s.erase(s.find_last_not_of( szDelims ) + 1);
  return s;
}
//-----------------------------------------------------------------------------
wstring wstr_trim(wstring const& p_s, const wchar_t* szDelims)
{
	std::wstring s = p_s;
	s.erase(0, s.find_first_not_of( szDelims ) );
	s.erase(s.find_last_not_of( szDelims ) + 1);
	return s;
}
//-----------------------------------------------------------------------------
std::wstring normalize_phone(wstring sPhone, wchar_t& prefix)
{
    const size_t c_expected_phone_len = 11;
    sPhone = wstr_trim(sPhone);
    if( sPhone.empty() )
        return sPhone;

    sPhone.erase(std::remove(sPhone.begin(), sPhone.end(), L' '), sPhone.end());
    prefix = sPhone[0];
    const wchar_t toEraseChars[] = L"()-+=";
    sPhone.erase(
        std::remove_if(sPhone.begin(), sPhone.end(), 
                       [&toEraseChars](auto wch){
                           return std::find(std::begin(toEraseChars), std::end(toEraseChars), wch) != std::end(toEraseChars);
                       }
        ),
        sPhone.end()
    );
    
    if (c_expected_phone_len == sPhone.length())
    {
        if (prefix == L'8') sPhone[0] = L'7';
    }

    return sPhone;
}
//-----------------------------------------------------------------------------
std::wstring normalize_phone(wstring sPhone, bool add_plus, bool& was_plus)
{
    const size_t c_expected_phone_len = 11;
    wchar_t prefix{};
    sPhone = normalize_phone(sPhone, prefix);
    was_plus = prefix == L'+';
    if (c_expected_phone_len == sPhone.length())
    {
        if (add_plus) sPhone.insert(0, 1, L'+');
    }
    return sPhone;
}
//-----------------------------------------------------------------------------
std::wstring normalize_phone(wstring sPhone, bool add_plus)
{
    bool was_plus{};
    return normalize_phone(sPhone, add_plus, was_plus);
}
//-----------------------------------------------------------------------------
int nprintf_to_buf(char* buf, size_t buf_size, size_t count, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	assert(buf_size > count);
#ifdef _WINDOWS
	int rc = vsnprintf_s(buf, buf_size, count, fmt, args);
#else
	(void)buf_size;
	int rc = vsnprintf(buf, count, fmt, args);
#endif
	va_end(args);
	return rc;
}
//-----------------------------------------------------------------------------
int scanf_from_buf(const char* buf, const char* format, ...) 
{
    va_list args;
    va_start(args, format);
#ifdef _WINDOWS
    int rc = vsscanf_s (buf, format, args);
#else
    int rc = vsscanf(buf, format, args);
#endif
    va_end(args);
    return rc;
}
//-----------------------------------------------------------------------------
int swcanf_from_buf(const wchar_t* buf, const wchar_t* format, ...) 
{
    va_list args;
    va_start(args, format);
#ifdef _WINDOWS
    int rc = vswscanf_s(buf, format, args);
#else
    int rc = vswscanf(buf, format, args);
#endif
    va_end(args);
    return rc;
}
//-----------------------------------------------------------------------------
std::string error_string(int err)
{
	std::array<char, 256> buf;
#ifdef _WINDOWS
	errno_t rc;
	rc = strerror_s(buf.data(), buf.size(), err);
#else
	error_t rc{};
    std::ignore = strerror_r(err, buf.data(), buf.size());
#endif
	if( rc )
		nprintf_to_buf(buf.data(), buf.size(), buf.size() - 1, "Error #%d", err);
	return buf.data();
}
//-----------------------------------------------------------------------------
int is_file_access(const char* file, int mode)
{
#ifdef _WINDOWS
	return _access(file, mode);
#else
	return access(file, mode);
#endif
}
//-----------------------------------------------------------------------------
int unlink_file(const char* file)
{
#ifdef _WINDOWS
	return _unlink(file);
#else
	return unlink(file);
#endif
}
//-----------------------------------------------------------------------------
bool	copy_file(const char* src_path, const char* dst_path)
{
	std::ifstream ifs(src_path, ios_base::in | ios_base::binary);
	std::ofstream ofs(dst_path, ios_base::out | ios_base::binary | ios_base::trunc);
	std::array<char, 512> buf;
	while(ifs.good() )
	{	
		ifs.read(&buf.front(), buf.max_size());
		ofs.write(&buf.front(), ifs.gcount());
	}
	return true;
}
//-----------------------------------------------------------------------------
/// @parse_url - разбирает URL по упрощенной схеме protocol://host[:port][/path]
bool parse_url(const wchar_t* url, std::wstring* protocol, 
			   std::wstring* host, int* port, std::wstring* path)
{
	if(!url || !*url) return false;

	if( protocol ) protocol->clear();
	if( path )	   path->clear();
	if( port )	   *port = 80;
	if( host )	   host->clear();

	std::wstring s_url = url;
	size_t  i = s_url.find(L"//");
	if( wstring::npos != i )
	{	
		if( protocol ) *protocol = s_url.substr(0, i + 2);
		s_url = s_url.substr(i + 2);
	}
	
	i = s_url.find(L'/');
	if( wstring::npos != i && path ) *path = s_url.substr(i);
	s_url = s_url.substr(0, i);
	i = s_url.find(L':');
	if( port ) *port = 80;
	if( wstring::npos != i && port ) *port = wcstol(s_url.substr(i + 1).c_str(), NULL, 10);
	if( host ) *host = s_url.substr(0, i);
	return true;
}
//-----------------------------------------------------------------------------
long long int str_version_to_int64(const char* ver)
{
	string s_ver = ver && *ver ? ver : "";
	long long int ver_as_int64 = 0LL;
	istringstream iss(s_ver);
	
	for( int N = 3; N >= 0 && iss.good(); --N )
	{
		unsigned short v = 0LL;
		char delim = '\0';
		iss >> v >> delim;
		ver_as_int64 += static_cast<long long int>(v) << (N*16);
	}
	return ver_as_int64;
}
//-----------------------------------------------------------------------------
bool is_update_info_need(time_t tt_last_update, 
						 unsigned interval, unsigned timeout, 
						 short upd_hh, short upd_mm, 
						 const char* kind_of_update)
{
	// infologger_t	&v_logger = the_logger(), *logger = &v_logger;

	time_t tt_now = std::time(nullptr);
	std::tm loc_tm = get_localtime(&tt_now);
	time_t tt_now_loc = mktime(&loc_tm);
	std::tm loc_tm_X = loc_tm;
	loc_tm_X.tm_min  = upd_mm % 60;
	loc_tm_X.tm_hour = upd_hh % 24;
	time_t tt_loc_X = mktime(&loc_tm_X);
	
	if( !kind_of_update ) kind_of_update = "resolv";

	// if(logger)
	// {
	// 	logger->debug() << "is_update_info_need\tkind is:\t" << kind_of_update << std::endl;
	// 	logger->debug() << "\tm_resolv_intrv: " <<  interval << std::endl;
	// 	logger->debug() << "\tm_resolv_timeout: "  << timeout << std::endl; 
	// 	logger->debug() << "\tloc_tm_X.tm_min: " <<  loc_tm_X.tm_min << std::endl;
	// 	logger->debug() << "\tloc_tm_X.tm_hour: "  << loc_tm_X.tm_hour << std::endl;
	// 	logger->debug() << "\ttt_now: " <<  tt_now << std::endl;
	// 	logger->debug() << "\ttt_now_loc: "  << tt_now_loc << std::endl;
	// 	logger->debug() << "\ttt_loc_X: "  << tt_loc_X << std::endl;
	// }

	double diff = 0 == tt_last_update ? 0.0 : difftime(tt_now, tt_last_update);
	double diff_X = difftime(tt_now_loc, tt_loc_X);
	double diff_tt = 0 == tt_last_update ? 0.0 : difftime(tt_last_update, tt_loc_X);

	// if(logger)
	// {
	// 	logger->debug() << "\ttt_last_update: " <<  tt_last_update << std::endl;
	// 	logger->debug() << "\tdiff(tt_now, tt_last_update): "  << diff << std::endl;
	// 	logger->debug() << "\tdiff(tt_now_loc, tt_loc_X): "  << diff_X << std::endl; 
	// 	logger->debug() << "\tdiff(tt_last_update, tt_loc_X): "  << diff_tt << std::endl;
				  
	// }

	// Условие обновления: 
	// (diff_X >= 0.0 && diff_X <= m_resolv_intrv && !(diff_tt >= 0 && diff_tt <= m_resolv_intrv)) || diff >= m_resolv_timeout 
	
	if( (diff_X < 0.0 || diff_X > double(interval) || (diff_tt >= 0.0 && diff_tt <= double(interval))) 
		&& fabs(diff) < double(timeout)
	  )
	{
		// if(logger)
        //     logger->info() << "\tupdate NOT NEEDED:\t" << kind_of_update <<  std::endl;
		return false;
	}
	// if(logger)
    //     logger->info() << "\tNEED TO UPDATE!:\t" << kind_of_update <<  std::endl;
	return true;
}
//-----------------------------------------------------------------------------
unsigned get_32bit_cheque_num(unsigned ExtChequeNum)
{
	static bool b_init = false;
	static int  cnt = 0;

	if( cnt++ == RAND_MAX ) b_init = false;

	if( !b_init )
	{
		b_init = true;
		cnt = 0;
		srand(static_cast<unsigned>(time(nullptr)));
	}

	if(!ExtChequeNum) ExtChequeNum = static_cast<unsigned>( time(nullptr) );
	ExtChequeNum %= 86400;

	unsigned rnd = rand() % 32767;

	return (rnd << 17) | ExtChequeNum;
}

//-----------------------------------------------------------------------------------------
unsigned sleep_execution(unsigned seconds)
{
#ifdef _WINDOWS
	Sleep(seconds*1000L);
	return 0;
#else
	return sleep(seconds);
#endif
}
//-----------------------------------------------------------------------------------------
/// @round_to - выполняет банковское округление с заданной точностью знаков после запятой
/// @param [in]  v	      - округляемое число.
/// @param [in]  decimals - точность, число знаков после запятой (если < 0, то округляется до 10^decimals).
//-----------------------------------------------------------------------------------------
double round_to(double v, int decimals)
{
	bool is_neg_decimals = decimals < 0;
	decimals = std::abs(decimals);
	size_t N = decimals; decimals = 1; 
	while( N-- ) decimals *= 10;
	v = is_neg_decimals ?  v / static_cast<double>(decimals) : v * static_cast<double>(decimals) ; 
	v = rounding::roundhalfeven( v ); 
	v = is_neg_decimals ?  v * static_cast<double>(decimals) : v / static_cast<double>(decimals) ; 
	return v;
}
//-----------------------------------------------------------------------------------------
/// @math_round_to - выполняет математическое округление с заданной точностью знаков после запятой
/// @param [in]  v	      - округляемое число.
/// @param [in]  decimals - точность, число знаков после запятой (если < 0, то округляется до 10^decimals).
//-----------------------------------------------------------------------------------------
double math_round_to(double v, int decimals)
{
	bool is_neg_decimals = decimals < 0;
	decimals = std::abs(decimals);
	size_t N = decimals; decimals = 1; 
	while( N-- ) decimals *= 10;
	v = is_neg_decimals ?  v / static_cast<double>(decimals) : v * static_cast<double>(decimals) ; 
	v = rounding::roundhalfup( v ); 
	v = is_neg_decimals ?  v * static_cast<double>(decimals) : v / static_cast<double>(decimals) ; 
	return v;
}
//-----------------------------------------------------------------------------------------
/// @seredina_bool_from_wstr - разбирает строку как bool
bool seredina_bool_from_wstr( const std::wstring& s )
{
    return (s[0] == L'1' || s == L"true") ? true : 
           (s[0] == L'0' || s == L"false") ? false : false;
} 
//-----------------------------------------------------------------------------------------
/// @seredina_tribool_from_wstr - разбирает строку как трехзначный bool
seredina_tribool_t seredina_tribool_from_wstr( const std::wstring& s )
{
    return (s[0] == L'1' || s == L"true") ? seredina_tribool_true : 
        (s[0] == L'0' || s == L"false") ? seredina_tribool_false : seredina_tribool_intermediate;
} 
//-----------------------------------------------------------------------------------------
/// @seredina_tribool_to_wstr - форматирует строку как как трехзначный bool "", "true", "false"
std::wstring seredina_tribool_to_wstr( const seredina_tribool_t b)
{
    return seredina_tribool_true == b ? L"true" : seredina_tribool_false == b ? L"false" : 
           L"";
} 
//-----------------------------------------------------------------------------------------
/// @seredina_tribool_to_wstr_as_int - форматирует строку как как трехзначный bool "", "1", "0"
std::wstring seredina_tribool_to_wstr_as_int( const seredina_tribool_t b )
{
    return seredina_tribool_true == b ? L"1" : seredina_tribool_false == b ? L"0" : 
            L"" ;
} 
//-----------------------------------------------------------------------------------------


//-----------------------------------------------------------------------------
/// @translate_err_msg - перевод сообщения с указанным кодом. 
/// если текста об ошибке с кодом err_code нет - возвращается orig_msg;
//-----------------------------------------------------------------------------
// Используем обычный вектор из std::pair<int, const wchar_t*>, либо просто массив
// и линейный поиск по коду. 
struct ErrMsgTextEl : public std::pair<int, std::wstring>
{
	ErrMsgTextEl(int err, const wchar_t* errtxt)
		: std::pair<int, std::wstring>(err, errtxt)
	{	}
};

using ErrMsgTextCont = std::vector<ErrMsgTextEl>;

std::wstring translate_err_msg(int err_code, const std::wstring& orig_msg)
{
	static ErrMsgTextCont  vErrMessages {
		{80241, L"Карта не найдена"},
		{81400, L"Недостаточно бонусов или в компьютер не введены анкетные данные владельца карты"},
		{82040, L"Карта находится в статусе завершена или выпущена из оборота."},
		{4, L"Не удалось изменить данные клиента в CRM"},
		{1, L"Время ожидания сервера истекло. Повторите попытку."},
		{81301, L"Чек с таким номером, с данной кассы, сегодня уже был создан. Чек не будет проведен."},
		{82001, L"Касса с таким номером не найдена."},
		{81321, L"Нет позиции для возврата или не все коды товаров определены"}, 
		{81328, L"Сумма чека не совпадает с суммой по позициям"}, 
		{81341, L"Магазин с таким кодоим не найден"},
		{81380, L"Чек с таким номером не найден"},
		{80106, L"Срок действия карты истек"},
		{110051, L"Карта принадлежит другому клиенту."}, 
		{80001, L"Не найдена Карта"}, 		
		{80040, L"Не найдена Карта"}, 		
		{80080, L"Не указан номер новой Карты"}, 		
		{80081, L"Не найдена Карта"}, 		
		{80082, L"Не найдена новая Карта"}, 		
		{80083, L"Различаются Контакты старой и новой Карт"}, 		
		{80084, L"Различаются Мастер-счета старой и новой Карт"}, 		
		{80085, L"Ошибка при установке статуса Карты"}, 		
		{80086, L"Ошибка при обновлении новой Карты"}, 		
		{80087, L"Ошибка при обновлении новой Карты"}, 		
		{80088, L"Ошибка при обновлении новой Карты"}, 		
		{80100, L"Не найдена Карта"}, 		
		{80180, L"Не найденаКарта"}, 		
		{80220, L"Не найдена Карта"}, 		
		{80242, L"Карт с таким номером больше одной"}, 		
		{80243, L"Некорректный параметр тип Бонуса"}, 		
		{80244, L"Некорректный параметр у статуса Карты"}, 		
		{80245, L"Не задана дата статуса"}, 		
		{80280, L"Не указана Карта"}, 
		{80281, L"Неверная команда"}, 
		{80300, L"Ошибка при обновлении Карты"}, 
		{80320, L"Запрещена смена статуса Карты"}, 
		{80360, L"Не указан номер Карты"}, 
		{80361, L"Неверно указан статус Карты"}, 
		{80362, L"Не найдена Карта"},
		{80363, L"Не найден POS"}, 
		{80400, L"Неверно указан тип операции"}, 
		{80420, L"Операция запрещена по статусу Карты"}, 
		{85040, L"Нет доступа в CRM"},
		{85041, L"Не найден параметр"},
		{86800, L"Не найден Контакт"}, {82720, L"Не найдена Карта"},
		{82721, L"Неверно указан тип операции"}, {82722, L"Не указана кампания"}, 
		{82723, L"Скидка и Бонус не могут быть одновременно равны нулю"},
		{82724, L"Скидка не может быть меньше нуля"}, 
		{82725, L"Скидка и Бонус не могут быть указаны одновременно"}, 
		{82726, L"Скидка не может быть на списание"}, 
		{82727, L"Дата окончания действия Бонуса не может быть меньше текущей даты"}, 
		{82728, L"Неверно указан тип операции"}, {82729, L"Операция запрещена по статусу Карты"},
		{82730, L"Неверный тип коррекции"},
		{82731, L"При данном типе коррекции должен быть указан идентификатор Бонуса"},
		{89121, L"Не указан Бонус"}, {89122, L"Нет такого Бонуса"},
		{82740, L"Ошибка определения пользователя или нет доступа в CRM"},
		{82741, L"Не найден Бонус"}, {82742, L"Бонус не скидочный"},
		{82760, L"Ошибка определения пользователя или нет доступа в CRM"}, 
		{82761, L"Ошибка получения информации о задании "}, 
		{82781, L"Контакт не найден"}, {86920, L"Ошибка в статусе"}, {86921, L"Не найдена строка"}, 
		{82000, L"Не указан POS"}, {81100, L"Не найден чек"}, {81101, L"Не указан номер Карты"}, 
		{81102, L"Не указан POS"}, {81103, L"Не указана дата либо задана в ошибочном формате"}, 
		{81104, L"Не указана сумма"}, {81105, L"Не указан признак наличия позиций"},
		{81106, L"Не указан признак наличия платежей"},
		{81107, L"Не указан тип операции"}, {81108, L"Ошибка в признаке наличия позиций"}, 
		{81109, L"Ошибка в признаке наличия платежей"}, {81110, L"Ошибка в типе операции"}, 
		{81111, L"Ошибка в сумме оплаты Бонусом"}, {81112, L"Не найдены строки чека"},
		{81120, L"Не найдены строки чека"}, {81121, L"Не найдены платежи чека"}, 
		{81122, L"Сумма чека не соответствует сумме по позициям чека"}, 
		{81123, L"Не указана дата и время чека"},
		{81124, L"Некорректный формат даты и\\или времени в чеке"}, 
		{81125, L"Не указана дата и\\или время в чеке"}, {81126, L"Сумма чека не может быть меньше нуля"},
		{81127, L"Скидка по чеку не может быть меньше нуля"},
		{81128, L"Сумма со скидкой не может быть отрицательным значением"}, 
		{81129, L"Оплачиваемые Бонусы не могут быть отрицательным значением"},
		{81130, L"Цена в позиции чека не может быть отрицательной величиной"}, 
		{81131, L"Количество в позиции чека не может быть отрицательным значением"},
		{81132, L"Сумма по позиции чека не может быть отрицательным значением"},
		{81133, L"Скидка по позиции чека не может быть отрицательным значением"}, 
		{81134, L"Сумма со скидкой по позиции чека не может быть отрицательным значением"}, 
		{81135, L"Бонус по позиции чека не может быть отрицательным значением"}, 
		{81180, L"Не задан код чека"}, {81260, L"Не найден чек"}, {81261, L"Были списания начисленных этим чеком Бонусов"}, 
		{81262, L"Ошибка при удалении чека"}, {81320, L"Не найдены позиции чека"},
		{81322, L"Не все номера позиций определены"}, {81323, L"Не все суммы позиций определены"}, 
		{81324, L"Не все суммы позиций со скидкой определены"},
		{81325, L"Не все цены позиций определены"}, {81326, L"Не все количества позиций определены"}, 
		{81327, L"Не все скидки по позициям определены"}, 
		{81329, L"Сумма чека со скидкой не совпадает с суммой по позициям"}, 
		{81330, L"Не все коды товаров идентифицированы"}, {81340, L"Не найден организация"},
		{81342, L"Не найден POS"}, 		{81343, L"Не найден магазин"},
		{81344, L"Не найдена организация"}, {81360, L"Не найдены платежи по чеку"}, 
		{81361, L"Не все типы платежей определены"}, {81362, L"Не все суммы платежей определены"}, 
		{81363, L"Сумма чека со скидкой не совпадает с суммой платежей"}, 
		{81364, L"Не все типы платежей идентифицированы"}, 
		{81381, L"Отмена транзакции возможна только с того же POS, с которого был основной чек"},
		{81382, L"Отмена транзакции возможна только по той же Карте, по которой был основной чек"}, 
		{81420, L"Не найден ни один активный шаблон операции Списание по чеку"},
		{81421, L"Найдено более одного активного шаблона операции Списание по чеку"},
		{83080, L"Не найдено задание"}, {83081, L"Не указан отправитель e-mail"}, {86000, L"Не задан логин"}, 
		{86001, L"Не задан пароль"}, {86002, L"Не задан IP"}, {86020, L"Не задан логин"}, 
		{86021, L"Не задан пароль"}, {86022, L"Не задан IP"}, {86060, L"Параметр @cardid не определен"},
		{86061, L"Параметр @parenttype не определен"}, {86062, L"Недопустимое значение параметра @parenttype"}, 
		{86160, L"Сессия не найдена"}, {86161, L"Недостаточно прав для выполнения данной операции"}, 
		{89040, L"Параметр с таким коротким названием уже существует!"}, {86220, L"Параметр @cardid неопределен"}, 
		{89060, L"Нет доступа в CRM"}, {86440, L"Не задан номер Карты"}, {86460, L"Не задан логин"}, 
		{86461, L"Найдено ни одного"}, {86462, L"Найдено более одного Контакта с указанным логином"}, 
		{86480, L"Не указан Контакт"}, {86481, L"Ошибочный тип сообщения"}, {86482, L"Не найден тип задачи"}, 
		{86483, L"Не найден Контакт"}, {86484, L"Не задан пароль"}, {86485, L"Не найден отправитель"},
		{86486, L"Отсутствует тело сообщения"}, {86487, L"Не задан адрес e-mail"}, {86488, L"Не указан отправитель e-mail"},
		{86489, L"Отсутствует тело e-mail"}, {86490, L"Не указан номер телефона"}, 
		{86491, L"Не указан телефон отправителя"}, {86900, L"Сообщение с номером %d не найдено (статус \"%s\")!"},
		{86901, L"Сообщение с внешним номером %d не найдено (статус \"%s\")!"},
		{86902, L"Ошибка установления статуса \"%s\" сообщения с идентификатором %d"}, 
		{86903, L"Ошибка установления статуса \"%s\" сообщения с внешним идентификатором %d"}, 
		{80340, L"Недопустимое значение параметров @set_mode и @skip_check"}, {86520, L"Сессия не найдена"},
		{81302, L"Невозможно оплатить больше, чем указано в чеке"}, {84121, L"Не найден POS"},
		{84061, L"Не указан номер чека"}, {84062, L"Ошибка в номере чека"},
		{84141, L"Не указан номер предыдущего чека"}, {84101, L"Не указан тип операции"}, 
		{84102, L"Неверный тип операции"}, {84103, L"Операция не реализована"}, 
		{84042, L"Карта не найдена"}, {84043, L"Срок действия Карты еще не начат"}, 
		{84044, L"Срок действия Карты истек"}, {84045, L"Карта не активна"}, {84201, L"Такой чек уже обработан"},
		{84202, L"Неверно указан номер чека для возврата"}, {84203, L"Чек для возврата не найден"}, 
		{84204, L"Чек для возврата не найден"}, {84205, L"Неверный тип чека"}, {84206, L"Номера Карт не совпадают"}, 
		{84207, L"Суммы чеков не совпадают"}, {84208, L"Возврат по чеку уже совершен"}, {84021, L"Запрос баланса невозможен"},
		{84022, L"Карта не найдена"}, {84001, L"Карта не найдена"}, {84002, L"Карта уже активирована"}, 
		{84003, L"Карта заблокирована"}, {84004, L"Карта закрыта"}, {84005, L"Карта завершена"},
		{84006, L"Неизвестный статус"}, {84007, L"Карта не может быть активирована"},
		{89146, L"Нельзя передавать сумму оплаты баллами в чек возврата"},
		{80000, L"Внутренняя ошибка"} 	
}; 
		
	std::wstring err_msg = orig_msg;

	auto p = std::find_if(vErrMessages.begin(), vErrMessages.end(),
						  [=](auto p_el) {return p_el.first == err_code;  }
			 );

	if( vErrMessages.end() != p  ) err_msg = p->second;
	return err_msg;
} 
//-----------------------------------------------------------------------------

} // namespace Seredina{
