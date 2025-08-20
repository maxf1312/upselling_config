#ifndef __SETTINGS_H__
#define __SETTINGS_H__
#include "zsutilsexp.h"

namespace Seredina{
	ZSUTILS_API extern const char* const c_crypter_name;
	class  SettingsError : public std::logic_error
	{
	public:
		SettingsError(const std::string& _Message) : std::logic_error(_Message) {}
	};

	class  SettingNotFound : public SettingsError
	{
	public:
		SettingNotFound(const std::string& _Message) : SettingsError(_Message) {}
	};
	
	class  CannotLoadSettings : public SettingsError
	{
	public:
		CannotLoadSettings(const std::string& _Message) : SettingsError(_Message) {}
	};

	class  SettingBadName : public SettingsError
	{
	public:
		SettingBadName(const std::string& _Message) : SettingsError(_Message) {}
	};

	typedef std::vector<std::string> TStringArray;

	struct ZSUTILS_API ISettings;
	struct ZSUTILS_API ISetting
	{
	public: 
		virtual				~ISetting()	{ ; }
		virtual	ISetting*	clone() const = 0;
		virtual	std::string	Name() const = 0;
		virtual	std::string	FullName() const = 0;
		virtual	ISettings*	AsSettings() const = 0;

		virtual	bool		encoded()	    const = 0;
		virtual	void		encoded(bool b)       = 0;
		
		virtual	std::string	AsString() const = 0;
		virtual	bool		AsBool() const = 0;
		virtual	int			AsInt() const = 0;
		virtual	unsigned	AsUInt() const = 0;
		virtual	double		AsDouble() const = 0;
		virtual	TStringArray	AsArray() const = 0;
		
		virtual	void		AsString(const char*) = 0;
		virtual	void		AsBool(bool) = 0;
		virtual	void		AsInt(int) = 0;
		virtual	void		AsUInt(unsigned) = 0;
		virtual	void		AsDouble(double) = 0;
		virtual	void		AsArray(const TStringArray&) = 0;

		virtual	void		FromString(const char*) = 0;
		virtual	void		FromBool(bool) = 0;
		virtual	void		FromInt(int) = 0;
		virtual	void		FromUInt(unsigned) = 0;
		virtual	void		FromDouble(double) = 0;
		virtual	void		FromArray(const TStringArray&) = 0;
	};
	
	enum SettingsSrcType{SettingsSrcIni, SettingsSrcXML};
	struct ZSUTILS_API ISettings
	{
	public: 
		virtual			    ~ISettings() { ; }
		virtual	size_t		size() const = 0;
		virtual	ISetting&	item(const char* name) const = 0;
		//virtual	ISetting&	item_by_val(const char* name, const char* v) const = 0;
		virtual	ISetting&	item_add(const char* name, bool as_val) const = 0;
		virtual	ISetting&	item_add(const char* name) const = 0;
		virtual	ISetting&	at(size_t index) const = 0;
		virtual	bool		encoded()	    const = 0;
		virtual	void		encoded(bool b)       = 0;
		virtual void		load(SettingsSrcType source_type, const char* source_addr) = 0;
		virtual void		save(SettingsSrcType dest_type, const char* dest_addr) const = 0;
		//virtual void		clear() = 0;
		virtual ISettings*  clone() const = 0;
	};

	ZSUTILS_API ISettings*	CreateSettings(const char* settings_info);
	ZSUTILS_API ISettings*	TestCteateSettings();

	
};


#endif // __SETTINGS_H__
