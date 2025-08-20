#pragma once

#include <string>

namespace ProLoyalty{

/// Типы кодовых страниц
enum CodePages {
    cpDEF = -1,          // default application locale's code page
    cpACP = 0,           // default to ANSI code page
    cpOEMCP = 1,           // default to OEM  code page
    cpMACCP = 2,           // default to MAC  code page
    cpTHREAD_ACP= 3,           // current thread's ANSI code page
    cpSYMBOL = 42,          // SYMBOL translations
    cpUTF7 = 65000,       // UTF-7 translation
    cpUTF8 = 65001       // UTF-8 translation
};


/// Тип для ид транзакции
typedef long long int id_transaction_t;

/// Тип для данных о прокси
struct PLCORE_API proxy_info_data
{
	std::wstring m_proxy;
	std::wstring m_proxybypass;
	std::wstring m_proxyusr;
	std::wstring m_proxypsw;

	proxy_info_data(const wchar_t* proxy, const wchar_t* proxybypass,
					const wchar_t* proxyusr, const wchar_t* proxypsw);
	proxy_info_data(const char* proxy, const char* proxybypass,
					const char* proxyusr, const char* proxypsw);
};


};

