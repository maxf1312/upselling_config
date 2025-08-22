#pragma once

#include <libplcore/plcorexp.h>

namespace ProLoyalty {
	
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

	/// @brief Интерфейс Настройки, одного значения
	struct PLCORE_API ISettings;
	struct PLCORE_API ISetting
	{
	public:
		using Ptr = std::unique_ptr<ISetting>;

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
	/// @brief Интерфейс Коллекции Настроек, одного значения
	struct PLCORE_API ISettings
	{
	public:
		using Ptr = std::unique_ptr<ISettings>;
		virtual			    ~ISettings() { ; }
		virtual	size_t		size() const = 0;
		virtual	ISetting&	item(const char* name) const = 0;
		virtual	ISetting&	item_add(const char* name, bool as_val) const = 0;
		virtual	ISetting&	item_add(const char* name) const = 0;
		virtual	ISetting&	at(size_t index) const = 0;
		virtual	bool		encoded()	    const = 0;
		virtual	void		encoded(bool b)       = 0;
		virtual void		load(SettingsSrcType source_type, const char* source_addr) = 0;
		virtual void		save(SettingsSrcType dest_type, const char* dest_addr) const = 0;
		virtual ISettings*  clone() const = 0;
	};

	PLCORE_API ISettings*	CreateSettings(const char* settings_info);
	PLCORE_API ISettings*	TestCteateSettings();
	
};
