#pragma once

#include <ctime>
#include <libplcore/plcorexp.h>

typedef struct tag_seredina_response seredina_response_t; 

namespace ProLoyalty{

PLCORE_API inline double time_t_to_oledate(std::time_t t){ return static_cast<double>((t + 25569.0*86400.0)/86400.0); }
PLCORE_API inline std::time_t oledate_to_time_t(double d){ return static_cast<std::time_t>(d*86400.0 - 25569.0*86400.0); }
PLCORE_API std::time_t	gmtime_to_localtime(std::time_t const& r_gmt, std::time_t* p_lmt);

PLCORE_API inline	double begin_of_the_day(double d){ return static_cast<int>(d); }
PLCORE_API inline	double end_of_the_day(double d)  { return begin_of_the_day(d) + 86399.0/86400.0; }
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
/// @format_time_t - форматировать time_t, строка формата как для strftime, 
/// @param [in] as_local - если true, значит время берется локальное
PLCORE_API std::string format_time_t(const std::time_t tt, const char* fmt, bool as_local);
//-----------------------------------------------------------------------------
/// @format_time_t - форматировать time_t, строка формата как для strftime
/// @param [in] as_local - если true, значит время берется локальное
PLCORE_API std::wstring format_time_t(const std::time_t tt, const wchar_t* fmt, bool as_local);
//-----------------------------------------------------------------------------
/// @format_oledatetime - форматировать time_t, строка формата как для strftime, 
PLCORE_API std::string  format_oledatetime(const double dt, const char* fmt);
PLCORE_API std::string  format_oledatetime(const double dt, const std::string& fmt);
//-----------------------------------------------------------------------------
/// @format_oledatetime - форматировать time_t, строка формата как для strftime, 
PLCORE_API std::wstring format_oledatetime(const double dt, const wchar_t* fmt);
PLCORE_API std::wstring format_oledatetime(const double dt, const std::wstring& fmt);
PLCORE_API std::tm get_localtime(const std::time_t *time);
PLCORE_API std::tm get_gmtime(const std::time_t *time);

} // namespace ProLoyalty


