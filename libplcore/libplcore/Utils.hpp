#pragma once 

#include <libplcore/plposprocdefs.h>
#include <libplcore/plcorexp.h>
#include <libplcore/UtilsTypes.hpp>

typedef struct tag_seredina_response seredina_response_t; 
//enum seredina_tribool_t;

namespace ProLoyalty{

struct LocaleSetter
{
    int m_categ;
    const char* m_prev_loc;
    LocaleSetter(int categ, const char* loc_nm);
    ~LocaleSetter();
};


PLCORE_API std::string toUTF8( const std::wstring &input, unsigned cp = cpUTF8  );
PLCORE_API std::wstring toUTF16( const std::string &input, unsigned cp = cpUTF8  );
PLCORE_API std::wstring toUTF16( const std::string &input, const char* locale_nm  );

PLCORE_API double begin_of_the_month(double d);
PLCORE_API double end_of_the_month(double d);

//-----------------------------------------------------------------------------
/// @oledate_to_ctime_tm
/// TODO часы минуты секунды
//-----------------------------------------------------------------------------
PLCORE_API void oledate_to_ctime_tm(double d, std::tm& t);
PLCORE_API std::tm oledate_to_ctime_tm(double d);

//-----------------------------------------------------------------------------
/// @ctime_tm_to_oledate
/// Converts struct tm to OLEDATE (as double)
//-----------------------------------------------------------------------------
PLCORE_API double ctime_tm_to_oledate(std::tm const& t);
//-----------------------------------------------------------------------------
/// @oledate_to_ctime_tm
/// Converts from OLEDATE to std::tm
//-----------------------------------------------------------------------------
PLCORE_API void oledate_to_ctime_tm(double d, std::tm& t);
//-----------------------------------------------------------------------------
/// @calc_age_in_years
/// Calculates age from birthday to today
/// if today is 0.0 assume it as is equal local_day()
//-----------------------------------------------------------------------------
PLCORE_API int calc_age_in_years(double birthday, double today);
//-----------------------------------------------------------------------------
/// @parse_xsd_date
/// Parses XSD date in formats: YYYY-MM-DD or YYYYMMDD
//-----------------------------------------------------------------------------
PLCORE_API double parse_xsd_date(const std::wstring& sDate);
//-----------------------------------------------------------------------------
/// @parse_RU_date
/// Parses date in RU format: DD.MM.YYYY or DD.MM.YY or DDMMYYYY or DDMMYY 
//-----------------------------------------------------------------------------
PLCORE_API double parse_RU_date(const std::wstring& sDate);
//-----------------------------------------------------------------------------
/// @parse_xsd_dateTime
/// Parses XSD dateTime in formats: YYYY-MM-DDThh:mm:ss or YYYYMMDDThhmmss
//-----------------------------------------------------------------------------
PLCORE_API double parse_xsd_dateTime(const std::wstring& sDateTime);
PLCORE_API double parse_xsd_dateTime(const std::string& sDateTime);

//-----------------------------------------------------------------------------
/// @id_transaction_t_from(to)
/// Set of conversion functions
//-----------------------------------------------------------------------------
PLCORE_API id_transaction_t  id_transaction_t_from_string(const std::string& s);
PLCORE_API std::string		  id_transaction_t_to_string(const id_transaction_t& t);
PLCORE_API id_transaction_t  id_transaction_t_from_wstring(const std::wstring& s);
PLCORE_API std::wstring	  id_transaction_t_to_wstring(const id_transaction_t& t);

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
PLCORE_API 
void parse_proc_id(const wchar_t* processing_id, std::wstring& processor_id, std::wstring& path_to_ini);
PLCORE_API inline 
void parse_proc_id(const std::wstring& processing_id, std::wstring& processor_id, std::wstring& path_to_ini)
{
	parse_proc_id(processing_id.c_str(), processor_id, path_to_ini);
}

//-----------------------------------------------------------------------------
/// Разбирает шаблон слип-чека tmpl и формирует чек на основании данных чека, 
/// переданных в объектах req и res.
/// @param [in]  tmpl - строка c шаблоном слип-чека
/// @param [in]  req  - объект с запросом чека
/// @param [in]  resp - объект с ответом чека
/// 
//-----------------------------------------------------------------------------
class CRequest;
class CResponse;
PLCORE_API 
std::wstring get_cheque_sleep_by_template(const std::wstring& tmpl, const CRequest& req, const CResponse& resp);

//-----------------------------------------------------------------------------
/// Разбирает шаблон слип-чека tmpl и формирует чек на основании данных чека, 
/// переданных в объектах req и res.
/// @param [in]  tmpl - строка c шаблоном слип-чека
/// @param [in]  req  - объект с запросом чека
/// @param [in]  resp - объект с ответом чека
/// @param [in]  org_title - строка - название магазина 
/// @param [in]  org_www   - строка - адрес сайта
/// @param [in]  curr_nm   - строка - название валюты
/// 
//-----------------------------------------------------------------------------
PLCORE_API 
std::wstring get_cheque_sleep_by_template(const std::wstring& tmpl, 
										  const CRequest& req, 
										  const CResponse& resp, 
										  const std::wstring& org_title,
										  const std::wstring& org_www,
										  const std::wstring& curr_nm);


//-----------------------------------------------------------------------------
/// @get_home_dir Возвращает домашний каталог и его указанную поддиректорию.  
/// переданных в объектах req и res.
/// @param [in]  sub_dir - подкаталог, если NULL - значит пустая строка.
/// 
//-----------------------------------------------------------------------------
PLCORE_API std::wstring get_home_dir(const wchar_t* sub_dir);
PLCORE_API inline std::wstring get_home_dir(const std::wstring& sub_dir)
{
	return get_home_dir(sub_dir.c_str());
}
PLCORE_API std::wstring get_config_dir();
PLCORE_API std::wstring get_log_dir();
PLCORE_API std::wstring get_log_nm(const wchar_t* suffix);
PLCORE_API inline std::wstring get_log_nm(const std::wstring& suffix)
{
	return get_log_nm(suffix.c_str());
}
PLCORE_API std::wstring get_log_path(const wchar_t* suffix = L"gs");
PLCORE_API inline std::wstring get_log_path(const std::wstring& suffix)
{
	return get_log_path(suffix.c_str());
}
PLCORE_API std::wstring get_db_dir();
PLCORE_API std::wstring get_tmp_dir();
PLCORE_API std::wstring get_bin_dir();
PLCORE_API std::wstring get_lib_dir();

//-----------------------------------------------------------------------------
/// @path_from_utf16 конвертирует путь к файлу из UTF16 в текущую кодировку приложения
/// @param [in]  path - путь. Если NULL - значит пустая строка.
//-----------------------------------------------------------------------------
PLCORE_API std::string  path_from_utf16(const wchar_t* path);
PLCORE_API std::string  path_from_utf16(const std::wstring& path);
//-----------------------------------------------------------------------------
/// @path_to_utf16 конвертирует путь к файлу в UTF16 из текущей кодировки приложения
/// @param [in]  path - путь. Если NULL - значит пустая строка.
//-----------------------------------------------------------------------------
PLCORE_API std::wstring path_to_utf16(const char* path);
PLCORE_API std::wstring path_to_utf16(const std::string& path);

//-----------------------------------------------------------------------------
/// @translate_err_msg - перевод сообщения с указанным кодом. 
/// если текста об ошибке с кодом err_code нет - возвращается orig_msg;
//-----------------------------------------------------------------------------
PLCORE_API std::wstring translate_err_msg(int err_code, const std::wstring& orig_msg);

//-----------------------------------------------------------------------------
/// @normalize_file_nm Нормализует имя файла из относительного в абсолютное.  
/// @param [in]  fn - имя файла, если NULL - значит имя wscardterm.ini.
/// 
//-----------------------------------------------------------------------------
PLCORE_API std::wstring normalize_file_nm(const wchar_t* fn);

//-----------------------------------------------------------------------------
/// @normalize_ini_file_nm Нормализует имя файла настройки из относительного
/// в абсолютное, учитывая возможность значения по умолчанию.
/// @param [in]  ini_file - имя файла, если NULL - значит имя wscardterm.ini.
/// @param [in]  needed_ext - требуемое(ожидаемое) расширение, начинается с '.'
//-----------------------------------------------------------------------------
PLCORE_API std::wstring normalize_ini_file_nm(const wchar_t* ini_file,
											   const wchar_t* needed_ext);

//-----------------------------------------------------------------------------
PLCORE_API std::string			str_to_upper  (std::string  const& s);
PLCORE_API std::wstring		wstr_to_upper (std::wstring const& s);

//-----------------------------------------------------------------------------
/// @str_trim и @wstr_trim - реализация trim для string и wstring
PLCORE_API std::string&		str_trim( std::string& s, const char* szDelims = " \t\r\n");
PLCORE_API std::wstring&		wstr_trim(std::wstring& s, const wchar_t* szDelims = L" \t\r\n");

PLCORE_API std::string			str_trim( std::string const& s, const char* szDelims = " \t\r\n");
PLCORE_API std::wstring		wstr_trim(std::wstring const& s, const wchar_t* szDelims = L" \t\r\n");

template <typename CharT>
std::basic_string<CharT>& string_trim(std::basic_string<CharT>& s, const CharT* szDelims)
{
  s.erase(0, s.find_first_not_of( szDelims ) );
  s.erase(s.find_last_not_of( szDelims ) + 1);
  return s;
}

template <typename CharT>
std::basic_string<CharT> string_trim(std::basic_string<CharT> const& p_s, const CharT* szDelims)
{
	std::basic_string<CharT> s(p_s);
	s.erase(0, s.find_first_not_of( szDelims ) );
	s.erase(s.find_last_not_of( szDelims ) + 1);
	return s;
}
//-----------------------------------------------------------------------------
template <typename CharT>
struct trim_delimiters_t
{
	static const CharT * const value;  
};

template <>
struct trim_delimiters_t<char>
{
	static const char * const value;// = " \t\r\n";  
};

template <>
struct trim_delimiters_t<wchar_t>
{
	static const wchar_t * const value; // = L" \t\r\n";  
};

template <typename CharT>
std::basic_string<CharT> trim_string(std::basic_string<CharT> const& s, 
									 const CharT* szDelims = trim_delimiters_t<CharT>::value)
{
	std::basic_string<CharT> r(s);
	r.erase(0, r.find_first_not_of( szDelims ) );
	r.erase(r.find_last_not_of( szDelims ) + 1);
	return r;
}
//-----------------------------------------------------------------------------
template <typename CharT>
std::basic_string<CharT>& str_replace(std::basic_string<CharT>& s,
									  const std::basic_string<CharT>& old_str,
						  		      const std::basic_string<CharT>& new_str,
									  typename std::basic_string<CharT>::size_type pos,
									  typename std::basic_string<CharT>::size_type* next_pos)
{
	typename std::basic_string<CharT>::size_type i = s.find(old_str, pos);
	if( std::basic_string<CharT>::npos != i )
	{
		s.replace(i, old_str.length(), new_str);
		if( next_pos ) *next_pos = i + new_str.length();
	}
	return s;
}
//-----------------------------------------------------------------------------
template <typename CharT>
std::basic_string<CharT>& str_replace_all(std::basic_string<CharT>& s,
										  const std::basic_string<CharT>& old_str,
						  				  const std::basic_string<CharT>& new_str,
									      typename std::basic_string<CharT>::size_type pos,
									      typename std::basic_string<CharT>::size_type* next_pos)
{
	typename std::basic_string<CharT>::size_type next = pos;
	do
	{
		pos = next;
		s = str_replace(s, old_str, new_str, pos, &next);
	
	}
	while(next != pos);
	if( next_pos ) *next_pos = next;    
	return s;
}
//-----------------------------------------------------------------------------
inline std::wstring& wstr_replace(std::wstring& s, const std::wstring& old_str, 
						  	      const std::wstring& new_str, 
					      std::wstring::size_type pos = 0, 
						  std::wstring::size_type* next_pos = NULL)
{
	return str_replace(s, old_str, new_str, pos, next_pos);
}
//-----------------------------------------------------------------------------
inline std::wstring& wstr_replace_all(std::wstring& s, const std::wstring& old_str, 
						  	      const std::wstring& new_str, 
					      std::wstring::size_type pos = 0, 
						  std::wstring::size_type* next_pos = NULL)
{
	return str_replace_all(s, old_str, new_str, pos, next_pos);
}

//-----------------------------------------------------------------------------
/// Сравнение строк на равенство без учета регистра
struct is_string_equals_ci_basicstr_tag;
template <typename CType, typename CTag = is_string_equals_ci_basicstr_tag>
bool is_string_equals_ci(const std::basic_string<CType>& s1, const std::basic_string<CType>& s2)
{
    return s1.length() == s2.length() &&
        std::equal(s1.begin(), s1.end(), s2.begin(), s2.end(),
                   [](auto c1, auto c2)
    {
        return toupper(c1) == toupper(c2);
    }
    );
}
//-----------------------------------------------------------------------------
template <typename CType>
bool is_string_equals_ci(const CType* s1, const CType* s2)
{
    return (!s1 && !s2) || (!*s1 && !*s2) || (s1 && s2 && is_string_equals_ci(std::basic_string<CType>{s1}, std::basic_string<CType>{s2}));
}

//-----------------------------------------------------------------------------
/// Разбивает строку на части по указанным разделителям 
template <typename CType>
std::vector<std::basic_string<CType> > split(const std::basic_string<CType>& s, const CType* delim)
{
    std::vector<std::basic_string<CType> > fields;

    size_t first = 0, found = std::basic_string<CType>::npos;
    do
    {
        found = s.find_first_of(delim, first);
        fields.emplace_back(s.substr(first, std::basic_string<CType>::npos != found ? found - first : std::basic_string<CType>::npos));
        first = std::basic_string<CType>::npos != found ? found + 1 : std::basic_string<CType>::npos;
    } while (std::basic_string<CType>::npos != found);
    return fields;
}
//-----------------------------------------------------------------------------
template <typename CharT>
struct quote_char_t
{
    static const CharT value;
};

template <>
struct quote_char_t<char>
{
    static const char value;// = '\"';  
};

template <>
struct quote_char_t<wchar_t>
{
    static const wchar_t value; // = L'\"';  
};

//-----------------------------------------------------------------------------
/// Корректирует поля в массиве, получившемся из строки с разделителями, чтобы строки с кавычками были в одном поле
template <typename CType>
std::vector<std::basic_string<CType> > 
correct_splitted_quotted_fields(std::vector<std::basic_string<CType> > fields,
    const CType delim_char,
    const CType quote_char = quote_char_t<CType>::value,
    const CType* space_delimiters = trim_delimiters_t<CType>::value)
{
    const size_t npos = std::basic_string<CType>::npos;
    bool         concatenate_mode = false;

    for(auto p = fields.begin(); p != fields.end() ; ++p)
    {
        size_t  first = p->find_first_not_of(space_delimiters); 
        if (npos == first) continue;

        size_t last = p->find_last_not_of(space_delimiters);
        if (npos == last) continue;

        size_t first_found = p->find(quote_char, first);
        size_t last_found = p->rfind(quote_char, last);
        if (!concatenate_mode) 
        {
            if (first_found == first )
            { 
                if (last_found == last) { continue; }
                else { concatenate_mode = true; }
            }
        }
        else 
        {
            p[-1] += delim_char;
            p[-1] += *p;
            fields.erase(p--);

            if (last_found == last) concatenate_mode = false;
        }
    }
    return fields;
}
//-----------------------------------------------------------------------------
/// Удаляет обрамляющие кавычки 
template <typename CType> std::basic_string<CType> 
remove_framing_quotes(std::basic_string<CType> s, 
                      const CType quote_char = quote_char_t<CType>::value,
                      const CType* space_delimiters = trim_delimiters_t<CType>::value)
{
    const size_t npos = std::basic_string<CType>::npos;

    size_t  first = s.find_first_not_of(space_delimiters);
    if (npos == first) return s;

    size_t first_found = s.find(quote_char, first);
    if (first_found == first) s.erase(0, first_found + 1);

    size_t last = s.find_last_not_of(space_delimiters);
    if (npos == last) return s;

    size_t last_found = s.rfind(quote_char, last);
    if (last_found == last) s.erase(last_found, s.length() - last_found);
    return s;
}

//-----------------------------------------------------------------------------
/// @format_time_t - форматировать time_t, строка формата как для strftime, 
/// @param [in] as_local - если true, значит время берется локальное
PLCORE_API std::string format_time_t(const time_t tt, const char* fmt, bool as_local);
//-----------------------------------------------------------------------------
/// @format_time_t - форматировать time_t, строка формата как для strftime
/// @param [in] as_local - если true, значит время берется локальное
PLCORE_API std::wstring format_time_t(const time_t tt, const wchar_t* fmt, bool as_local);
//-----------------------------------------------------------------------------
/// @format_oledatetime - форматировать time_t, строка формата как для strftime, 
PLCORE_API std::string  format_oledatetime(const double dt, const char* fmt);
PLCORE_API std::string  format_oledatetime(const double dt, const std::string& fmt);
//-----------------------------------------------------------------------------
/// @format_oledatetime - форматировать time_t, строка формата как для strftime, 
PLCORE_API std::wstring format_oledatetime(const double dt, const wchar_t* fmt);
PLCORE_API std::wstring format_oledatetime(const double dt, const std::wstring& fmt);

//-----------------------------------------------------------------------------
/// @check_struct_ptr
//-----------------------------------------------------------------------------
template <typename T>
int check_struct_ptr(T* p)
{
	return !p || p->size_of_struct != sizeof(T) ? SEREDINA_ERR_INVARG : SEREDINA_ERR_OK;
}

//-----------------------------------------------------------------------------
/// @init_struct_t structures's initializer
//-----------------------------------------------------------------------------
template <typename T>
void init_struct_t(T& s, bool no_zero = false)
{
	if( !no_zero )
		memset(&s, 0, sizeof(T));
	s.size_of_struct = sizeof(T);
}
//-----------------------------------------------------------------------------
/// @iif_values_with_cast 
//-----------------------------------------------------------------------------
template <typename T1, typename T2>
T2 iif_values_with_cast(const T1 v1, const T1 v_neq, const T2 v2)
{
	T2 r = v2;
	if( v1 != v_neq ) r = static_cast<T2>(v1);
	return r;
}

template <size_t N>
inline const wchar_t* wchararr_2_pwchar(wchar_t (&rArr)[N])
{
	if( !N ) return L"";
	if( L'\0' != rArr[N - 1] ) rArr[N - 1] = L'\0'; 
	return L'\0' == rArr[0] ? L"" : rArr;
}

template <size_t N>
inline const wchar_t* wchararr_2_pwchar(wchar_t const (&rArr)[N])
{
	return wchararr_2_pwchar(const_cast<wchar_t (&)[N]>(rArr)); 
}

inline wchar_t* copy_2_wchararr_impl(wchar_t* p_dest, size_t N, const wchar_t* p_src)
{
#ifdef _WINDOWS
	wcsncpy_s(p_dest, N, p_src, N - 1);
#else
	wcsncpy(p_dest, p_src, N - 1);
#endif // _WINDOWS
	p_dest[N - 1] = L'\0';
	return p_dest;
}

template <size_t N>
inline wchar_t* copy_2_wchararr(wchar_t (&r_dest)[N], const wchar_t* p_src)
{
	return copy_2_wchararr_impl(r_dest, N, p_src);
}

template <size_t N>
inline wchar_t* copy_2_wchararr(wchar_t (&r_dest)[N], const wchar_t* p_src, const wchar_t* elipsis)
{
    wchar_t* r = copy_2_wchararr_impl(r_dest, N, p_src);
    if( elipsis && wcslen(p_src) >= N && wcslen(elipsis) < N )
    {
        wcscpy(&r_dest[N - 1 - wcslen(elipsis)], elipsis);
    }
    return r;
}

template <size_t N, typename StrT>
inline wchar_t* copy_2_wchararr(wchar_t (&r_dest)[N], const StrT& s_src)
{
	return copy_2_wchararr_impl(r_dest, N, s_src.c_str());
}

template <size_t N>
inline bool is_wchararr_elipsis(wchar_t const (&r_dest)[N], const wchar_t* elipsis)
{
    if( elipsis && wcslen(elipsis) < N )
    {
        return 0 == wcscmp(&r_dest[N - 1 - wcslen(elipsis)], elipsis);
    }
    return false;
}

//-----------------------------------------------------------------------------
/// @del_and_null
//-----------------------------------------------------------------------------
template <typename T>
void del_and_null(T* (&p))
{
	delete p; p = NULL;
}


//-----------------------------------------------------------------------------
/// @get_val - шаблон для получения значения объекта через метод T ContT::getV() const;
//-----------------------------------------------------------------------------
template<typename T, typename ContT>
T get_val(ContT& obj, T (ContT::* mem_obj)() const)
{
	return (obj.*mem_obj)();
}

//-----------------------------------------------------------------------------
/// @Owned_Inner_Ptr_t - шаблон для хранящегося указателя на внутренний объект
//                       (например, стратегию и коллекцию настроек)   
//-----------------------------------------------------------------------------
template<typename T>
class PLCORE_API Owned_Inner_Ptr_t
{
    bool owned_;
    T*   ptr_;
    T*  (*clone_fun_)(T*);
    typedef Owned_Inner_Ptr_t<T> ThisClass;
public:
    Owned_Inner_Ptr_t(): owned_(false), ptr_(NULL), clone_fun_(NULL){}
    Owned_Inner_Ptr_t(T* p, bool owned): owned_(owned), ptr_(p), clone_fun_(NULL) {}
    Owned_Inner_Ptr_t(T* p, bool owned, T* (*clone_fun)(T*)) : owned_(owned), ptr_(p), clone_fun_(clone_fun)
    {
        if( owned && clone_fun )
            ptr_ = clone_fun(p);
    }
    
    Owned_Inner_Ptr_t(const Owned_Inner_Ptr_t& rhs) : owned_(rhs.owned_), ptr_(rhs.ptr_), clone_fun_(rhs.clone_fun_) 
    {  
        if( !owned_ )
            return;
        if( !clone_fun_ )
            const_cast<Owned_Inner_Ptr_t&>(rhs).set_owned(false);
        else if( rhs.ptr_ )
            ptr_ = clone_fun_(rhs.ptr_);
    }
    ~Owned_Inner_Ptr_t()
    {
        set_ptr( NULL );
    }

    Owned_Inner_Ptr_t& operator=(const Owned_Inner_Ptr_t& rhs)
    {
        if( this != &rhs  )
        {
            Owned_Inner_Ptr_t tmp(rhs);
            std::swap(ptr_, tmp.ptr_);
            std::swap(owned_, tmp.owned_);
            std::swap(clone_fun_, tmp.clone_fun_);
        }
        return *this;
    }
    
    operator bool() const { return ptr_ != NULL; }
    operator bool()       { return const_cast<ThisClass const&>(*this); }
    T*  operator ->()         { return get_ptr(); }
    const T* operator ->() const   { return const_cast<ThisClass&>(this).get_ptr(); }

    bool    is_owned() const {  return owned_; }
    bool    set_owned(bool owned) {  bool b = owned_; owned_ = owned; return b; }
    
    T* get_ptr() const { return ptr_; }
    
    T* set_ptr(T* p, bool owned = false) 
    { 
        T* p_ret = ptr_;
        if( ptr_ != p )
        {
            if( owned_ )
                del_and_null( ptr_ ), p_ret = NULL;
            owned_ = owned;
            ptr_ = p;
        }
        return p_ret;
    }
};

//-----------------------------------------------------------------------------
/// @init_response_result_t - inits response buffer
//-----------------------------------------------------------------------------
PLCORE_API void init_response_result_t(seredina_response_t& resp);

//-----------------------------------------------------------------------------
PLCORE_API int nprintf_to_buf(char* buf, size_t buf_size, size_t count, const char* fmt, ...);
//-----------------------------------------------------------------------------
PLCORE_API int scanf_from_buf(const char* buf, const char* format, ...);
//-----------------------------------------------------------------------------
PLCORE_API int swcanf_from_buf(const wchar_t* buf, const wchar_t* format, ...);
//-----------------------------------------------------------------------------
PLCORE_API std::string error_string(int err);
//-----------------------------------------------------------------------------
PLCORE_API int is_file_access(const char* file, int mode);
//-----------------------------------------------------------------------------
PLCORE_API int unlink_file(const char* file);
//-----------------------------------------------------------------------------
inline int is_file_access(std::string const& file, int mode)
{
	return is_file_access(file.c_str(), mode);
}
inline int unlink_file(std::string const& file)
{
	return unlink_file(file.c_str());
}
//-----------------------------------------------------------------------------
PLCORE_API struct tm get_localtime(const time_t *time);
//-----------------------------------------------------------------------------
PLCORE_API struct tm get_gmtime(const time_t *time);

//-----------------------------------------------------------------------------
/// @open_db Открывает БД.  
/// @param [in]  conn_str - строка соединения в стиле ADO.
//-----------------------------------------------------------------------------
class SQLiteDB;
PLCORE_API void open_db(const wchar_t* conn_str, SQLiteDB& db);

//-----------------------------------------------------------------------------
/// @exec_sql Выполняет оператор SQL DML.  
/// @param [in]  sql	  - выполняемый оператор.
/// @param [in]  conn_str - строка соединения в стиле ADO.
//-----------------------------------------------------------------------------
typedef long long int rowid_t;
PLCORE_API int	exec_sql(const wchar_t* sql, const wchar_t* conn_str, rowid_t* last_rowid);
//-----------------------------------------------------------------------------
PLCORE_API
void save_cheque_request_to_db(const wchar_t* conn_str, 
							   CRequest const& chq, 
                               CResponse& res,
							   bool bIsSend, bool bIsRK, bool bIsVisa);
//-----------------------------------------------------------------------------
PLCORE_API bool update_dnsresolv_file( const wchar_t* base_url, 
										const wchar_t* Org, 
										const wchar_t* BUnit, 
										const wchar_t* POS, 
										std::wstring* err_msg,
										const proxy_info_data* proxy_info);
//-----------------------------------------------------------------------------
PLCORE_API bool update_settings_files( const wchar_t* base_url, 
										const wchar_t* ini_filename, 
										const wchar_t* Org, 
										const wchar_t* BUnit, 
										const wchar_t* POS, 
										std::wstring* err_msg,
										const proxy_info_data* proxy_info);
//-----------------------------------------------------------------------------
/// @download_file - загрузка файла, метод HTTP GET
PLCORE_API bool download_file(const wchar_t* url_to_file, 
				   const wchar_t* remote_filename,
				   const wchar_t* local_filename, 
				   const wchar_t* local_dstpath, 
				   std::wstring*  err_msg,
				   const proxy_info_data* proxy_info);
//-----------------------------------------------------------------------------
/// @parse_url - разбирает URL по упрощенной схеме protocol://host[:port][/path]
PLCORE_API bool parse_url(const wchar_t* url, 
							  std::wstring* protocol, std::wstring* host, 
							  int* port, std::wstring* path);
//-----------------------------------------------------------------------------
/// @is_update_info_need - определяет, необходимо ли обновление
PLCORE_API bool is_update_info_need(time_t tt_last_update, 
									 unsigned interval, unsigned timeout, 
									 short upd_hh, short upd_mm, 
									 const char* kind_of_update);
//-----------------------------------------------------------------------------
/// @get_32bit_cheque_num - получает случайный номер чека из номера с кассы ExtChequeNum.
/// Если ExtChequeNum равен 0 - берется значение time(NULL).
PLCORE_API unsigned get_32bit_cheque_num(unsigned ExtChequeNum);
//-----------------------------------------------------------------------------
/// @sleep_execution - приостанавливает выполнение на seconds секунд
PLCORE_API unsigned sleep_execution(unsigned seconds);
//-----------------------------------------------------------------------------
/// @url_escape - Выполняет URL escaping
PLCORE_API std::string url_escape(std::string const & s);
//-----------------------------------------------------------------------------
/// @normalize_phone - нормализует номер телефона для РФ в виде [+]7xxxxxxxxxxx
PLCORE_API std::wstring normalize_phone(std::wstring sPhone, bool add_plus);
//-----------------------------------------------------------------------------
/// @round_to - выполняет банковское округление с заданной точностью знаков после запятой
PLCORE_API double round_to(double v, int decimals);
//-----------------------------------------------------------------------------
/// @math_round_to - выполняет математическое округление с заданной точностью знаков после запятой
PLCORE_API double math_round_to(double v, int decimals);
//-----------------------------------------------------------------------------
/// @seredina_bool_from_wstr - разбирает строку как bool
PLCORE_API bool seredina_bool_from_wstr( const std::wstring& s );
//-----------------------------------------------------------------------------
/// @seredina_tribool_from_wstr - разбирает строку как трехзначный bool
PLCORE_API seredina_tribool_t seredina_tribool_from_wstr( const std::wstring& s );
//-----------------------------------------------------------------------------
/// @seredina_tribool_to_wstr - форматирует строку как как трехзначный bool "", "true", "false"
PLCORE_API std::wstring seredina_tribool_to_wstr( const seredina_tribool_t b);
//-----------------------------------------------------------------------------
/// @seredina_tribool_to_wstr_as_int - форматирует строку как как трехзначный bool "", "1", "0"
PLCORE_API std::wstring seredina_tribool_to_wstr_as_int( const seredina_tribool_t b );
//-----------------------------------------------------------------------------
/// @dump_dll_dep_from_path - выдет список зависимостей dll (.so) с флагом - загружается или нет
PLCORE_API std::vector<std::pair<std::string, bool>> dump_dll_dep_from_path(char const* path);
//-----------------------------------------------------------------------------
/// @get_random_str --> len - Длина строки <-- случайная строка ascii длины len
PLCORE_API std::string get_random_str(size_t len);
PLCORE_API std::wstring get_random_wstr(size_t len);
//-----------------------------------------------------------------------------


} // namespace ProLoyalty
