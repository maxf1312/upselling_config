#include <libplcore/stdafx.h>

#include <date/date.h>
#include <cstdlib>
#include <cmath>
#include <cstring>
#include <string>
#include <array>

#include <libplcore/Utils.hpp>
#include <libplcore/UtilsDate.hpp>


namespace ProLoyalty{

using namespace std;

//-----------------------------------------------------------------------------
std::tm oledate_to_ctime_tm(double d)
{
	std::tm t;
	oledate_to_ctime_tm(d, t);
	return t;
}
//-----------------------------------------------------------------------------
double begin_of_the_month(double d)
{
	std::tm gmt = oledate_to_ctime_tm(begin_of_the_day(d));

	gmt.tm_mday = 1;
	return ctime_tm_to_oledate(gmt);
}
//-----------------------------------------------------------------------------
double end_of_the_month(double d)
{
	std::tm gmt = oledate_to_ctime_tm(begin_of_the_day(d));
	gmt.tm_mday = 1;
	if( ++gmt.tm_mon > 11 ) gmt.tm_mon = 0, ++gmt.tm_year;
	return ctime_tm_to_oledate(gmt) - 1.0;
}
//-----------------------------------------------------------------------------
/// @ctime_tm_to_oledate
//-----------------------------------------------------------------------------
double ctime_tm_to_oledate(std::tm const& t)
{
	using namespace date;
	using namespace std::chrono;

	double d = 0.0;
	if( t.tm_mday )
	{
		auto d0{ 1899_y / 12 / 30 };
		auto d1{ year{ t.tm_year + 1900} / month{ static_cast<unsigned int>(t.tm_mon + 1)} / day{static_cast<unsigned int>(t.tm_mday)} };
		auto ld1 = sys_days(d1);
		auto ld0 = sys_days(d0);
		unsigned int ud = 0;
		if (ld0 <= ld1)	for (; ld0 < ld1; ld0 += days{ 1 }, ++ud);
		else            for (; ld0 > ld1; ld1 += days{ 1 }, ++ud);
		d = ud;
	}

	d += t.tm_hour/24.0;
	d += t.tm_min/(24.0*60);
	d += t.tm_sec/(24.0*60*60);
	
	return d;
}
//-----------------------------------------------------------------------------
/// @oledate_to_ctime_tm
/// Конвертирует из double в std::tm
//-----------------------------------------------------------------------------
void oledate_to_ctime_tm(double d, std::tm& t)
{
	using namespace date;
	using namespace std::chrono;

	memset(&t, 0, sizeof(std::tm));
	if (abs(d - 0.0) < 1.0 / (24 * 60 * 60))	return;

	// date - integer part of d
	double int_d;
	d = modf(d, &int_d);

	auto d0{ 1899_y / 12 / 30 };
	sys_days dd{ d0 };
	for (unsigned long int_dd = static_cast<unsigned long>(int_d); int_dd-- > 0; )	dd += days{ 1 };

	d0 = floor<days>(dd);

	t.tm_year = static_cast<int>(d0.year()) - 1900;
	t.tm_mon = static_cast<unsigned int>(d0.month()) - 1;
	t.tm_mday = static_cast<unsigned int>(d0.day());
	weekday wd {d0};
	t.tm_wday = wd.c_encoding();

	auto d_by{ year{d0.year()} / January / 1 };
	dd = d_by;
	for (t.tm_yday = 0; d0 > d_by ;  dd += days{ 1 }, d_by = dd ) ++t.tm_yday;
	
	// time - fractional part of d
	d *= 24.0;
	t.tm_hour = static_cast<int>(d); 
	d -= t.tm_hour;
	d *= 60.0;
	t.tm_min = static_cast<int>(d); 
	d -= t.tm_min;
	d *= 60;
	t.tm_sec = static_cast<int>(d);	
}
//-----------------------------------------------------------------------------
date::year_month_day oledate_to_gregorian_date(double d)
{
	using namespace date;
	using namespace std::chrono;
	auto d_d{ 1899_y / 12 / 30 };

	if (std::fabs (d - 0.0) >= 0.000001 )
	{
		std::tm t;
		oledate_to_ctime_tm(d, t);
		d_d = year_month_day(year{ t.tm_year + 1900 }, month{ static_cast<unsigned int>(t.tm_mon + 1) }, day{ static_cast<unsigned int>(t.tm_mday) });
	}
	return d_d;
}
//-----------------------------------------------------------------------------
/// @calc_age_in_years
/// Calculates age from birthday to today
/// if today is 0.0 assume it as is equal local_day()
//-----------------------------------------------------------------------------
int calc_age_in_years(double birthday, double today)
{
	using namespace date;
	using namespace std::chrono;
	int age = 0;
	auto d_today(fabs(today - 0.0) >= 0.000001 ? oledate_to_gregorian_date(today) : date::year_month_day( floor<days>(system_clock::now()) ));
	auto d_birthday(fabs(birthday - 0.0) >= 0.000001 ? oledate_to_gregorian_date(birthday) : date::year_month_day( floor<days>(system_clock::now()) ));

	for (; d_birthday < d_today; d_birthday += years{ 1 }, ++age);
	return age - (age ? 1 : 0);		
}


//-----------------------------------------------------------------------------
/// @parse_xsd_date
/// Parses XSD date in formats: YYYY-MM-DD or YYYY.MM.DD or YYYYMMDD
//-----------------------------------------------------------------------------
double parse_xsd_date(const std::wstring& sDate)
{
    std::tm t{};
	//memset(&t, 0, sizeof t);
    swcanf_from_buf(sDate.c_str(),
			wstring::npos != sDate.find(L'-') ? L"%04d-%02d-%02d" :
			wstring::npos != sDate.find(L'.') ? L"%04d.%02d.%02d" : L"%04d%02d%02d",
			&t.tm_year, &t.tm_mon, &t.tm_mday
	);
	if( t.tm_mon > 0  ) --t.tm_mon;
	if( t.tm_year > 0 ) t.tm_year -= 1900;
			
	return ctime_tm_to_oledate( t );
}

//-----------------------------------------------------------------------------
/// @parse_RU_date
/// Parses date in RU format: DD.MM.YYYY or DD.MM.YY or DDMMYYYY or DDMMYY 
//-----------------------------------------------------------------------------
double parse_RU_date(const std::wstring& sDate)
{
    std::tm t{};
	//memset(&t, 0, sizeof t);
    swcanf_from_buf(sDate.c_str(),
	 wstring::npos != sDate.find(L'.') ? L"%02d.%02d.%04d" : L"%02d%02d%04d", 
		&t.tm_mday, &t.tm_mon, &t.tm_year 
	);
	
	if( t.tm_year > 0 )
	{ 
		if( t.tm_year < 100 )
		{ 
			if( t.tm_year <= 50 ){ t.tm_year += 2000; } else { t.tm_year += 1900; }
		}
		t.tm_year -= 1900;
	}
	if( t.tm_mon > 0  ) --t.tm_mon;
			
	return ctime_tm_to_oledate( t );
}

//-----------------------------------------------------------------------------
/// @parse_xsd_dateTime
/// Parses XSD dateTime in formats: YYYY-MM-DDThh:mm:ss or YYYYMMDDThhmmss
//-----------------------------------------------------------------------------
double parse_xsd_dateTime(const std::wstring& sDateTime)
{
	return parse_xsd_dateTime(toUTF8(sDateTime));
}
//-----------------------------------------------------------------------------
double parse_xsd_dateTime(const std::string& sDateTime)
{
    std::tm tm{}; //memset(&tm, 0, sizeof tm);
    scanf_from_buf(
        sDateTime.c_str(),
		wstring::npos != sDateTime.find('-') && wstring::npos != sDateTime.find(':') ? 
		"%04d-%02d-%02dT%02d:%02d:%02d" : "%04d%02d%02dT%02d%02d%02d", 
		&tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
	if( tm.tm_mon > 0  ) --tm.tm_mon;
	if( tm.tm_year > 0 ) tm.tm_year -= 1900;
						
	return ctime_tm_to_oledate( tm );
}
//-----------------------------------------------------------------------------
time_t	gmtime_to_localtime(time_t const& r_gmt, time_t* p_lmt)
{
    std::tm struct_tm{};
	//memset(&struct_tm, 0, sizeof struct_tm);

	time_t dt = r_gmt;

	// надо узнать смещение между localtime и GMT, чтобы прибавить его к dt
	time_t lmt = time(NULL);
	struct_tm = get_gmtime(&lmt);
	time_t gmt = mktime(&struct_tm);
	time_t tm_bias = static_cast<time_t>(difftime(lmt, gmt));
	dt += tm_bias;

	if( p_lmt ) *p_lmt = dt;
	return dt;
}
//-----------------------------------------------------------------------------
string format_time_t(const time_t tt, const char* fmt, bool as_local)
{
	if(!fmt || !*fmt) fmt = "%Y-%m-%d %H:%M:%S";

	std::tm timeinfo = as_local ? get_localtime (&tt) : get_gmtime (&tt); 
    std::array<char, 128> sbuf;
    strftime (sbuf.data(), sbuf.max_size(), fmt, &timeinfo);
	return sbuf.data();
}
//-----------------------------------------------------------------------------
wstring format_time_t(const time_t tt, const wchar_t* fmt, bool as_local)
{
	string sfmt = toUTF8(fmt && *fmt ? fmt : L"%Y-%m-%d %H:%M:%S");
	return toUTF16(format_time_t(tt, sfmt.c_str(), as_local));
}

//-----------------------------------------------------------------------------
/// @format_oledatetime - форматировать time_t, строка формата как для strftime, 
string format_oledatetime(const double dt, const char* fmt)
{
	if(!fmt || !*fmt) fmt = "%Y-%m-%d %H:%M:%S";

	std::array<char, 128> sbuf;
	
	std::tm timeinfo;
	oledate_to_ctime_tm(dt, timeinfo);
	if( timeinfo.tm_year || timeinfo.tm_mday)
		strftime (sbuf.data(), sbuf.max_size(), fmt, &timeinfo);
	else
		sbuf[0] = '\0';
	return sbuf.data();
}
//-----------------------------------------------------------------------------
/// @format_oledatetime - форматировать time_t, строка формата как для strftime, 
wstring format_oledatetime(const double dt, const wchar_t* fmt)
{
	string sfmt = toUTF8(fmt && *fmt ? fmt : L"%Y-%m-%d %H:%M:%S");
	return toUTF16(format_oledatetime(dt, sfmt.c_str()));
}
//-----------------------------------------------------------------------------
std::string  format_oledatetime(const double dt, const std::string& fmt) 
{
	return format_oledatetime(dt, fmt.c_str());
}
//-----------------------------------------------------------------------------
std::wstring format_oledatetime(const double dt, const std::wstring& fmt) 
{
	return format_oledatetime(dt, fmt.c_str());
}

//-----------------------------------------------------------------------------
// шаблон для реализации переносимых и относительно безопасных localtime и gmtime
//-----------------------------------------------------------------------------
typedef struct tm  struct_tm_t;
template <typename api_time_func>
struct_tm_t time_t_to_tm(const time_t *time, api_time_func f)
{
	struct_tm_t tm, *p_r = nullptr; 
	memset(&tm, 0, sizeof tm);
#ifdef _WINDOWS
	errno_t err = 0;
	if( !(err = f(&tm, time)) ) p_r = &tm;
#else
	error_t err = 0;
	p_r = f(time, &tm);
#endif
	if( !p_r )
	{
		if(!err) err = errno;
		throw std::logic_error("time_t_to_tm error: " + error_string(err));
	}
	return tm = *p_r;
}
//-----------------------------------------------------------------------------
std::tm get_localtime(const time_t *time)
{
#ifdef _WINDOWS
	struct_tm_t tm = time_t_to_tm(time, localtime_s);
#else
	struct_tm_t tm = time_t_to_tm(time, localtime_r);
#endif
	return tm;
}
//-----------------------------------------------------------------------------
std::tm get_gmtime(const time_t *time)
{
#ifdef _WINDOWS
	struct_tm_t tm = time_t_to_tm(time, gmtime_s);
#else
	struct_tm_t tm = time_t_to_tm(time, gmtime_r);
#endif
	return tm;
}
//-----------------------------------------------------------------------------

}
