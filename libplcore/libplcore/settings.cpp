#include <libplcore/stdafx.h>

#include <functional>
#include <algorithm>
#include <sstream>
#include <limits>
#include <tinyxml2.h>
#include <SimpleIni.h>

#include <libplcore/Utils.hpp>
#include <libplcore/crypto.hpp>
#include <libplcore/settings.hpp>

namespace ProLoyalty
{
	using namespace std;
	using namespace std::placeholders;

	const char* const c_crypter_name = "base_crypter";
	
	/// @brief Логический Трехзначный флаг  
	enum TriStateBool{ boolEmpty, boolFalse, boolTrue };
	TriStateBool operator||(TriStateBool a, TriStateBool b)
	{
		if( boolEmpty == a && boolEmpty == b )	return boolEmpty;   
		if( boolTrue == a || boolTrue == b )	return boolTrue;   
		if( boolFalse == a || boolFalse == b )	return boolFalse;   
		return boolEmpty;
	}
	
	/// @brief Абстрактный Базовый класс для настройки 
	class Settings;
	class Setting : public ISetting
	{
	public:
		using Ptr_t = unique_ptr<Setting>;
		enum Type { typeNone, typeNode, typeString, typeInt, typeBool, typeDouble };

		Setting(Settings* owner, const char* nm);

		virtual					~Setting();
		virtual	Type			getType()		const = 0;
		virtual TriStateBool    Encoded()		const = 0;
		virtual void			Encoded(TriStateBool b) = 0;

		virtual	string			Name();
		virtual	string			FullName()	const;
		void					Name(std::string const& nm);

				Settings*		ToSettings() ;
		virtual	ISettings*		AsSettings() const;

		virtual string			Name()  const;
		Settings*				Owner() const;
		void					Owner(Settings* p, IStringCrypter* p_crypter);
		Setting*				Parent() const;
		virtual Setting*		Clone() const = 0;
		virtual	ISetting*		clone()		const;

		virtual	bool			encoded()	    const;
		virtual	void			encoded(bool b);

	private:
		string    m_name;
		Settings* m_owner;
	};
	//-------------------------------------------------------------------------------
	inline bool operator==(Setting::Ptr_t const& up, Setting const* p) { return up.get() == p; }
	//-------------------------------------------------------------------------------
	class ValSetting : public Setting
	{
	public:
		virtual					~ValSetting();	
								ValSetting(Settings* owner, const char* nm);		
		template<typename T>	ValSetting(Settings* owner, const char* nm, const T& t);
								ValSetting(const ValSetting& rhs);		

		virtual	Type			getType()  const;
		virtual TriStateBool	Encoded()  const;
		virtual void			Encoded(TriStateBool b);
		
		virtual	std::string		AsString()	const; 
		virtual	bool			AsBool()	const;
		virtual	int				AsInt()		const;
		virtual	unsigned		AsUInt()	const;
		virtual	double			AsDouble()	const;
		virtual TStringArray	AsArray()	const;
		
		virtual	void			AsString(const char*);
		virtual	void			AsBool(bool);
		virtual	void			AsInt(int);
		virtual	void			AsUInt(unsigned);
		virtual	void			AsDouble(double);
		virtual void			AsArray(const TStringArray&);

		virtual	void			FromString(const char* v);
		virtual	void			FromBool  (bool b);
		virtual	void			FromInt   (int i);
		virtual	void			FromUInt  (unsigned u);
		virtual	void			FromDouble(double d);
		virtual	void			FromArray(const TStringArray& a);
		
		virtual Setting*		Clone() const;

	private:
		template<typename T> void to_val(const T& v);

		string			m_val;
		TriStateBool	m_enc;
	};
	//-------------------------------------------------------------------------------
	class Settings : public ISettings
	{
	public: 
		using Ptr_t = unique_ptr<Settings>;
		//typedef std::vector<Setting*> SettingCont;
		typedef std::vector<Setting::Ptr_t> SettingCont;

		virtual			~Settings();
						Settings();
						Settings(const Settings& rhs); 
		Settings&		operator=(const Settings& rhs);

		Setting*		append(Setting* s);
		void			remove(Setting* s);
		Setting*		nodeOwner() const;
		void			nodeOwner(Setting* owner);
		SettingCont&	settings();
		SettingCont&	settings() const;
		void			clear();

		TriStateBool	keysHaveEncryptName()			const;
		void			keysHaveEncryptName(TriStateBool b);
		TriStateBool	valuesHaveEncryptName()			const;
		void			valuesHaveEncryptName(TriStateBool b);
		ISetting&		item_get_or_add(const char* name, bool add_when_not_found, bool as_val);

		// ISettings
		virtual	size_t		size()				   const;
		virtual	ISetting&	item(const char* name) const;
		//virtual	ISetting&	item_by_val(const char* name, const char* v) const; 
		virtual	ISetting&	item_add(const char* name, bool as_val) const;
		virtual	ISetting&	item_add(const char* name) const;		
		virtual	ISetting&	at(size_t index) const;
		virtual	bool		encoded()		const;
		virtual	void		encoded(bool b);
		virtual void		load(SettingsSrcType source_type, const char* source_addr);
		virtual void		save(SettingsSrcType dest_type, const char* dest_addr) const ;
		virtual ISettings*  clone() const;

	private: 
		SettingCont		m_settings;
		Setting*		m_owner;
		TriStateBool	m_keysHaveEncryptName;
		TriStateBool	m_valuesHaveEncryptName;
		bool			m_encoded;
	};
	//-------------------------------------------------------------------------------
	class NodeSetting : public Setting
	{
	public:
		virtual					~NodeSetting();	
								NodeSetting(Settings* owner, const char* nm);
								NodeSetting(const NodeSetting& rhs); 

		virtual	Type			getType()  const;
		virtual TriStateBool	Encoded()  const;
		virtual void			Encoded(TriStateBool b);

		virtual	ISettings*		AsSettings() const;
		virtual	std::string		AsString() const;
		virtual	bool			AsBool()   const; 
		virtual	int				AsInt()    const;
		virtual	unsigned		AsUInt()    const;
		virtual	double			AsDouble() const;
		virtual TStringArray	AsArray()	const;
		
		virtual	void			AsString(const char*);
		virtual	void			AsBool(bool);
		virtual	void			AsInt(int);
		virtual	void			AsUInt(unsigned);
		virtual	void			AsDouble(double);
		virtual void			AsArray(const TStringArray& a);

		virtual	void			FromString(const char*);
		virtual	void			FromBool(bool);
		virtual	void			FromInt(int);
		virtual	void			FromUInt(unsigned);
		virtual	void			FromDouble(double);
		virtual void			FromArray(const TStringArray&);

		virtual Setting*		Clone() const;
	private:
		Settings m_kids;
	};

	//-------------------------------------------------------------------------------
	// Implmentation
	//-------------------------------------------------------------------------------
	// Setting
	//-------------------------------------------------------------------------------
	Setting::Setting(Settings* owner, const char* nm) : m_owner(owner), m_name(nm ? nm : "") 
	{ 
		if( owner )
			owner->append(this);
	}
	//-------------------------------------------------------------------------------
	Setting::~Setting()			
	{ 
		if( m_owner )
			m_owner->remove(this);
	}
	//-------------------------------------------------------------------------------
	Settings*	Setting::ToSettings() { return static_cast<Settings*>(AsSettings()); }
	//-------------------------------------------------------------------------------
	Setting*	Setting::Parent() const
	{
		return m_owner ? m_owner->nodeOwner() : NULL;
	}
	//-------------------------------------------------------------------------------
	void		Setting::Owner(Settings* p, IStringCrypter* p_crypter)
	{
		if( m_owner == p ) return;

		TriStateBool b_PrevKeysEncrypt = boolEmpty, 
					 b_PrevValuesEncrypt = boolEmpty;

		if( m_owner )
		{
			b_PrevKeysEncrypt   = m_owner->keysHaveEncryptName();
			b_PrevValuesEncrypt = m_owner->valuesHaveEncryptName();
			m_owner->remove(this);
			m_owner = NULL;
		}	
		if( p )
		{
			p->append(this);
			m_owner = p;		
			
			// TODO Учесть необходимость дешифрования
			// Дешифруем, только если предыдущий владелец не имел атрибутов шифрования, 
			// а новый имеет атрибуты, равные True
			if( p_crypter && boolTrue == m_owner->valuesHaveEncryptName() && boolEmpty == b_PrevValuesEncrypt )
			{
				FromString(p_crypter->decrypt_string(AsString().c_str()).c_str());
			}

			if( p_crypter && boolTrue == m_owner->keysHaveEncryptName() && boolEmpty == b_PrevKeysEncrypt )
			{
				m_name = p_crypter->decrypt_string(m_name.c_str());
			}
		}
	}
	//-------------------------------------------------------------------------------
	inline std::string	Setting::Name()			 { return m_name; }
	//-------------------------------------------------------------------------------
	inline 	void		Setting::Name(std::string const& nm) { m_name = nm; }
	//-------------------------------------------------------------------------------
	std::string	Setting::FullName()	const 
	{
		string nm = m_name;
		for(Setting* p = Parent(); p ; p = p->Parent() ) nm = p->Name() + "/" + nm;			
		return nm;
	}
	//-------------------------------------------------------------------------------
	inline ISettings*	Setting::AsSettings() const { return NULL; }
	//-------------------------------------------------------------------------------
	inline std::string		Setting::Name()  const { return const_cast<Setting*>(this)->Name(); }
	//-------------------------------------------------------------------------------
	inline Settings*		Setting::Owner() const { return m_owner; }
	//-------------------------------------------------------------------------------
	ISetting*				Setting::clone() const { return Clone(); }
	//-------------------------------------------------------------------------------
	bool					Setting::encoded() const 
	{ 
		return Encoded() == boolTrue; 
	}
	//-------------------------------------------------------------------------------
	void					Setting::encoded(bool b) 
	{ 
		return Encoded(b ? boolTrue : boolFalse); 
	}

	//-------------------------------------------------------------------------------
	//  ValSetting
	//-------------------------------------------------------------------------------
	ValSetting::~ValSetting(){ }
	//-------------------------------------------------------------------------------
	ValSetting::ValSetting(Settings* owner, const char* nm) 
		: Setting(owner, nm), m_enc(boolEmpty) { }
	//-------------------------------------------------------------------------------
	template<typename T>
	ValSetting::ValSetting(Settings* owner, const char* nm, const T& t) 
		: Setting(owner, nm), m_enc(boolEmpty) 
	{ 
		to_val(t); 
	}
	//-------------------------------------------------------------------------------
	ValSetting::ValSetting(const ValSetting& rhs) 
		: Setting(NULL, rhs.Name().c_str()), m_enc(rhs.m_enc), m_val(rhs.m_val)
	{}		
	//-------------------------------------------------------------------------------
	Setting::Type	ValSetting::getType()  const				{ return typeString; }
	//-------------------------------------------------------------------------------
	TriStateBool	ValSetting::Encoded()  const		{ return m_enc; }
	//-------------------------------------------------------------------------------
	void			ValSetting::Encoded(TriStateBool b)	{ m_enc = b;    }
	//-------------------------------------------------------------------------------
	std::string	ValSetting::AsString()	const 
	{ 
		return m_val; 
	}
	//-------------------------------------------------------------------------------
	bool		ValSetting::AsBool()	const { return m_val == "1"; }
	//-------------------------------------------------------------------------------
	int			ValSetting::AsInt()		const { return atoi(m_val.c_str()); }
	//-------------------------------------------------------------------------------
	unsigned	ValSetting::AsUInt()	const { return strtoul(m_val.c_str(), NULL, 10); }
	//-------------------------------------------------------------------------------
	double		ValSetting::AsDouble()	const { return atof(m_val.c_str()); }
	//-------------------------------------------------------------------------------
	TStringArray ValSetting::AsArray() const
	{
		TStringArray result;
		istringstream f(m_val);
		string s;
		while (getline(f, s, ','))
		{
			size_t startpos = s.find_first_not_of(" \t\n");
			size_t endpos = s.find_last_not_of(" \t\n");
			if( std::string::npos != startpos )
			{
				s = s.substr( startpos, endpos - startpos + 1);
				if (!s.empty())
				{
					result.push_back(s);
				}
			}
		}
		return result;
	}

	//-------------------------------------------------------------------------------
	void		ValSetting::AsString(const char* v)		{ FromString(v); }
	//-------------------------------------------------------------------------------
	void		ValSetting::AsBool  (bool b)			{ FromBool(b); }
	//-------------------------------------------------------------------------------
	void		ValSetting::AsInt   (int i)				{ FromInt(i); }
	//-------------------------------------------------------------------------------
	void		ValSetting::AsUInt  (unsigned u)		{ FromUInt(u); }
	//-------------------------------------------------------------------------------
	void		ValSetting::AsDouble(double d)			{ FromDouble(d); }
	//-------------------------------------------------------------------------------
	void		ValSetting::AsArray(const TStringArray& a)		{ FromArray(a); }
	//-------------------------------------------------------------------------------
	void		ValSetting::FromString(const char* v)	{ m_val = v; }
	//-------------------------------------------------------------------------------
	void		ValSetting::FromBool  (bool b)			{ m_val = (b ? "1" : "0"); }
	//-------------------------------------------------------------------------------
	void		ValSetting::FromInt   (int i)			{ to_val(i); }
	//-------------------------------------------------------------------------------
	void		ValSetting::FromUInt  (unsigned u)		{ to_val(u); }
	//-------------------------------------------------------------------------------
	void		ValSetting::FromDouble(double d)		{ to_val(d); }
	//-------------------------------------------------------------------------------
	void ValSetting::FromArray(const TStringArray& a)
	{
		m_val.clear();
		for (int index =0; index < a.size(); index++)
		{
			m_val.append(a[index]);
			if (index < a.size() - 1)
			{
				m_val.append(",");
			}
		}
	}
	//-------------------------------------------------------------------------------
	Setting*	ValSetting::Clone() const
	{
		return new ValSetting(*this);
	}
	//-------------------------------------------------------------------------------
	template<typename T> 
	void ValSetting::to_val(const T& v)
	{
		ostringstream os;
		os << v;
		m_val = os.str(); 
	}
	
	//-------------------------------------------------------------------------------
	// NodeSetting
	//-------------------------------------------------------------------------------
	NodeSetting::~NodeSetting()	
	{ 
		; 
	}
	//-------------------------------------------------------------------------------
	NodeSetting::NodeSetting(Settings* owner, const char* nm) : Setting(owner, nm)  
	{ 
		m_kids.nodeOwner(this);
	}
	//-------------------------------------------------------------------------------
	NodeSetting::NodeSetting(const NodeSetting& rhs) 
		: Setting(NULL, rhs.Name().c_str()), m_kids(rhs.m_kids)  
	{ 
		m_kids.nodeOwner(this);
	}
	//-------------------------------------------------------------------------------
	Setting::Type	NodeSetting::getType()  const	{ return typeNode; }
	//-------------------------------------------------------------------------------
	TriStateBool	NodeSetting::Encoded()  const	
	{ 
		return m_kids.valuesHaveEncryptName(); 
	}
	//-------------------------------------------------------------------------------
	void			NodeSetting::Encoded(TriStateBool b)	{ m_kids.valuesHaveEncryptName(b); }	
	//-------------------------------------------------------------------------------
	ISettings*	NodeSetting::AsSettings() const 
	{ 
		return &const_cast<NodeSetting*>(this)->m_kids; 
	}
	//-------------------------------------------------------------------------------
	std::string	NodeSetting::AsString() const { return string(); }
	//-------------------------------------------------------------------------------
	bool		NodeSetting::AsBool()   const { return false; }
	//-------------------------------------------------------------------------------
	int			NodeSetting::AsInt()    const { return 0; }
	//-------------------------------------------------------------------------------
	unsigned	NodeSetting::AsUInt()    const { return 0; }
	//-------------------------------------------------------------------------------
	double		NodeSetting::AsDouble() const { return 0.0; }
	//-------------------------------------------------------------------------------
	TStringArray		NodeSetting::AsArray() const { return TStringArray(); }
	//-------------------------------------------------------------------------------
	void		NodeSetting::AsString(const char* v)	{ FromString(v); }
	//-------------------------------------------------------------------------------
	void		NodeSetting::AsBool  (bool b)			{ FromBool(b); }
	//-------------------------------------------------------------------------------
	void		NodeSetting::AsInt   (int i)			{ FromInt(i); }
	//-------------------------------------------------------------------------------
	void		NodeSetting::AsUInt  (unsigned u)		{ FromUInt(u); }
	//-------------------------------------------------------------------------------
	void		NodeSetting::AsDouble(double d)			{ FromDouble(d); }
	//-------------------------------------------------------------------------------
	void		NodeSetting::AsArray(const TStringArray& a)	{ FromArray(a); }
	//-------------------------------------------------------------------------------
	void		NodeSetting::FromString(const char*){}
	//-------------------------------------------------------------------------------
	void		NodeSetting::FromBool(bool){}
	//-------------------------------------------------------------------------------
	void		NodeSetting::FromInt(int) {}
	//-------------------------------------------------------------------------------
	void		NodeSetting::FromUInt(unsigned) {}
	//-------------------------------------------------------------------------------
	void		NodeSetting::FromDouble(double) {}
	//-------------------------------------------------------------------------------
	void		NodeSetting::FromArray(const TStringArray&) {}
	//-------------------------------------------------------------------------------
	Setting*	NodeSetting::Clone() const
	{
		return new NodeSetting(*this);
	}
	//-------------------------------------------------------------------------------

	//-------------------------------------------------------------------------------
	// Settings
	//-------------------------------------------------------------------------------
	static bool Setting_find_name(Setting::Ptr_t const& p, const char* nm)
	{
		return p->Name() == nm;
	}
	//-------------------------------------------------------------------------------
	// static void Setting_del(Setting* p)
	// {
	// 	delete p;
	// }
	//-------------------------------------------------------------------------------
	Settings::~Settings() 
	{ 
		// while(m_settings.size() > 0)
		// {
		// 	Setting* s = m_settings.back();
		// 	delete s;
		// }
		clear();
	}		
	//-------------------------------------------------------------------------------
	Settings::Settings() 
		: m_owner(NULL), m_keysHaveEncryptName(boolEmpty), m_valuesHaveEncryptName(boolEmpty), 
		m_encoded(true)
	{}
	//-------------------------------------------------------------------------------
	void	clone_and_add_setting(Setting::Ptr_t const& p, Settings* owner)
	{
		Setting::Ptr_t s{p->Clone()}; 
		s->Owner(owner, NULL);
		s.release();
	}
	//-------------------------------------------------------------------------------
	Settings::Settings(const Settings& rhs) 
			: m_owner(NULL), 
			m_keysHaveEncryptName(rhs.m_keysHaveEncryptName), 
			m_valuesHaveEncryptName(rhs.m_valuesHaveEncryptName), 
			m_encoded(rhs.m_encoded)			
	{
		std::for_each(rhs.m_settings.begin(), rhs.m_settings.end(), 
		 			  [this](Setting::Ptr_t const& p){ clone_and_add_setting(p, this); } 
		);
	}
	//-------------------------------------------------------------------------------
	Settings&	Settings::operator=(const Settings& rhs)
	{
		if( this != &rhs )
		{
			m_keysHaveEncryptName	= rhs.m_keysHaveEncryptName;
			m_valuesHaveEncryptName	= rhs.m_valuesHaveEncryptName; 
			m_encoded				= rhs.m_encoded;
			clear();
			std::for_each(rhs.m_settings.begin(), rhs.m_settings.end(), 
					      bind(clone_and_add_setting, _1, this) );
		}
		return *this;
	}
	//-------------------------------------------------------------------------------
	Setting* Settings::append(Setting* s)
	{
		SettingCont::iterator p = find(m_settings.begin(), m_settings.end(), s);
		if( m_settings.end() == p )
			m_settings.emplace_back(s);
		return s;
	}
	//-------------------------------------------------------------------------------
	void Settings::remove(Setting* s)
	{
		SettingCont::iterator p = find(m_settings.begin(), m_settings.end(), s);
		if( m_settings.end() == p ) return;
		m_settings.erase(p);			
	}
	//-------------------------------------------------------------------------------
	Setting*		Settings::nodeOwner() const			{ return m_owner; }
	//-------------------------------------------------------------------------------
	void			Settings::nodeOwner(Setting* owner)	{ m_owner = owner; }
	//-------------------------------------------------------------------------------
	Settings::SettingCont&	Settings::settings()					
	{ 
		return m_settings; 
	}
	//-------------------------------------------------------------------------------
	Settings::SettingCont&	Settings::settings() const			
	{ 
		return const_cast<Settings&>(*this).settings(); 
	}
	//-------------------------------------------------------------------------------
	void			Settings::clear()
	{
		// for_each(m_settings.begin(), m_settings.end(), std::ptr_fun(Setting_del));
		// m_settings.clear();
		m_settings.erase(begin(m_settings), end(m_settings));
	}
	//-------------------------------------------------------------------------------
	TriStateBool Settings::keysHaveEncryptName() const	
	{ 
		return m_keysHaveEncryptName; 
	}
	//-------------------------------------------------------------------------------
	void	Settings::keysHaveEncryptName(TriStateBool b)	{ m_keysHaveEncryptName = b; }
	//-------------------------------------------------------------------------------
	TriStateBool Settings::valuesHaveEncryptName()		const	
	{ 
		return m_valuesHaveEncryptName; 
	}
	//-------------------------------------------------------------------------------
	void Settings::valuesHaveEncryptName(TriStateBool b)	{ m_valuesHaveEncryptName = b; }
	//-------------------------------------------------------------------------------
	ISetting&	Settings::item_get_or_add(const char* name, bool add_when_not_found, bool as_val)  
	{
		if (!name || '\0' == *name)
		{ 
			if( !nodeOwner() ) throw SettingBadName((std::string("Setting bad name: \"") + name + "\""));
			return *nodeOwner();
		}

		// Extract name from begin to first occurence of character '/'	
		string nm, nm_rest = name; 
		string::size_type pos = nm_rest.find('/');
		nm = nm_rest.substr(0, pos);
		if( pos != string::npos )
			nm_rest = nm_rest.substr(pos + 1);
		else
			nm_rest.clear();
		
		auto p = find_if(m_settings.begin(), m_settings.end(), 
						   bind(Setting_find_name, _1, nm.c_str())				
						);

		if(p == m_settings.end())
		{
			if( !add_when_not_found )
				throw ProLoyalty::SettingNotFound(string("Setting '") + nm + "' was not found!");
			Setting* s = NULL;
			if( as_val && nm_rest.empty() )	s = new ValSetting(this, nm.c_str());
			else							s = new NodeSetting(this, nm.c_str());
			p = find(m_settings.begin(), m_settings.end(), s);
			if( m_settings.end() == p )
				throw std::logic_error(string("Setting '") + nm + "' was not added into settings!");
		}
		return (*p)->AsSettings() ? 
				( add_when_not_found ? 
					(*p)->AsSettings()->item_add(nm_rest.c_str(), as_val) : (*p)->AsSettings()->item(nm_rest.c_str()) ) 
				: **p;
	}
	//-------------------------------------------------------------------------------
	// ISettings
	size_t		Settings::size()				   const	{	return m_settings.size();	}		
	//-------------------------------------------------------------------------------
	ISetting&	Settings::item(const char* name) const 
	{
		return const_cast<Settings*>(this)->item_get_or_add(name, false, false);
	}
	//-------------------------------------------------------------------------------
	//ISetting&	Settings::item_by_val(const char* name, const char* v) const 
	//{
	//	if (!name || '\0' == *name)
	//	{ 
	//		if( !nodeOwner() ) throw std::logic_error("Setting bad name");
	//		return *nodeOwner();
	//	}
	//}
	//-------------------------------------------------------------------------------
	ISetting&	Settings::item_add(const char* name, bool as_val) const
	{
		return const_cast<Settings*>(this)->item_get_or_add(name, true, as_val);
	}
	//-------------------------------------------------------------------------------
	ISetting&	Settings::item_add(const char* name) const
	{
		return const_cast<Settings*>(this)->item_get_or_add(name, true, true);
	}
	//-------------------------------------------------------------------------------
	ISetting&	Settings::at(size_t index) const 
	{
		if (index >= m_settings.size()) throw std::logic_error("Setting bad index");
		return *m_settings[index];
	}
	//-------------------------------------------------------------------------------
	bool		Settings::encoded()		const	{ return m_encoded; }
	//-------------------------------------------------------------------------------
	void		Settings::encoded(bool b)			{ m_encoded = b; }		
	//-------------------------------------------------------------------------------
	ISettings*  Settings::clone() const
	{
		unique_ptr<ISettings> s = make_unique<Settings>(*this);
		return s.release();
	}		
	//-------------------------------------------------------------------------------
	static Setting::Type  getXmlElType(tinyxml2::XMLElement* xmlEl)
	{
		const char* el_tp = xmlEl->Attribute("_tp");
		if( !el_tp ) return Setting::typeNone;
		switch(*el_tp)
		{
			default: break;
			case 'S': return Setting::typeString;
			case 'N': return Setting::typeNode;
			case 'B': return Setting::typeBool;
			case 'I': return Setting::typeInt;
			case 'D': return Setting::typeDouble;
		}
		return Setting::typeNone;
	}
	//-------------------------------------------------------------------------------
	static TriStateBool   str_to_TriStateBool(const char* str_bool)
	{
		if (!str_bool || !*str_bool) return boolEmpty;
		if ('0' == *str_bool || is_string_equals_ci(str_bool, "false") ) return boolFalse;
		return '1' == *str_bool || is_string_equals_ci(str_bool, "true") ? boolTrue : boolFalse;
	} 
	//-------------------------------------------------------------------------------
	static const char* const TriStateBool_to_str(TriStateBool b)
	{
		if (boolTrue == b  ) return "1";
		if (boolFalse == b ) return "0";
		return "";
	} 
	//-------------------------------------------------------------------------------
	void	ParseXMLToSettings(Settings* settings, tinyxml2::XMLElement* xmlEl, IStringCrypter* p_crypter)
	{
		for( ; xmlEl ; xmlEl = xmlEl->NextSiblingElement() )
		{  					
			Setting::Type tp = getXmlElType(xmlEl);
			const char*   nm = xmlEl->Name();
			
			Setting* p_setting = NULL;
			
			if( !xmlEl->FirstChildElement() && tp != Setting::typeNode )
			{
				TriStateBool  b_keysHaveEncryptName   = settings->keysHaveEncryptName(), 
							  b_valuesHaveEncryptName = settings->valuesHaveEncryptName();
				TriStateBool  b_enc = str_to_TriStateBool(xmlEl->Attribute("_enc")); 
				
				const char *t = xmlEl->GetText() ? xmlEl->GetText() : "";
				std::string txt  = boolTrue == operator||(b_valuesHaveEncryptName, b_enc) && p_crypter ? 
									p_crypter->decrypt_string(t) : t;
				std::string name = boolTrue == b_keysHaveEncryptName && p_crypter ? p_crypter->decrypt_string(nm) : nm;
				
				// TODO порешать насчет создания элемента нужного типа
				p_setting = new ValSetting(settings, name.c_str(), txt.c_str());
				p_setting->Encoded( b_valuesHaveEncryptName || b_enc);
			}
			else
			{
				const char* enc_keys = xmlEl->Attribute("_enc_keys");
				const char* enc_vals = xmlEl->Attribute("_enc_vals");
				TriStateBool b_keysHaveEncryptName   = str_to_TriStateBool(enc_keys), 
							 b_valuesHaveEncryptName = str_to_TriStateBool(enc_vals);

				p_setting = new NodeSetting(settings, nm);
				p_setting->ToSettings()->keysHaveEncryptName(b_keysHaveEncryptName);
				p_setting->ToSettings()->valuesHaveEncryptName(b_valuesHaveEncryptName);
				ParseXMLToSettings(p_setting->ToSettings(), xmlEl->FirstChildElement(), p_crypter);
			}
		}
	}
	//-------------------------------------------------------------------------------
	// Рекурсивный проход по дереву настроек и дешифрование в соответствии с флагами шифрования
	void	DecryptSettings(Settings* settings, IStringCrypter* p_crypter)
	{
		if( !settings || !p_crypter ) return; 
		
		// вытащим флаги шифрования ключей и значений
		TriStateBool  b_keysHaveEncryptName   = settings->keysHaveEncryptName(), 
					  b_valuesHaveEncryptName = settings->valuesHaveEncryptName();

		for(size_t i = 0, N = settings->size(); i < N; ++i)
		{
			Setting& setting = static_cast<Setting&>(settings->at(i));
			
			if( boolTrue == b_keysHaveEncryptName )
				setting.Name( p_crypter->decrypt_string(setting.Name().c_str()) );
			
			TriStateBool  b_enc = setting.Encoded(); 

			if(Settings* children = setting.ToSettings())
			{
				DecryptSettings(children, p_crypter);
			}
			else
			{
				if( boolTrue == b_valuesHaveEncryptName || boolTrue == setting.Encoded() )
					setting.FromString( p_crypter->decrypt_string(setting.AsString().c_str()).c_str() );
			}
		}
	}
	//-------------------------------------------------------------------------------
	void SetNoDecryptFlags(Settings* p_settings)
	{
		// Ищем раздел настроек Meta, в котором описаны параметры, чтобы намерено не дешифровать отдельные параметры.
		// Meta/nodecrypt_par - имя параметра для флагов не дешифруемых параметров, сами параметры отображаются на биты в 
		//                      секции Meta/nodecrypt_flags, где имя параметра равно значению флага, 
		//						а значение - Имени параметра, который не дешифровать. 
		ISettings* p_meta = p_settings->item_add("Meta", false).AsSettings();
		std::string nodecrypt_par = p_meta->item_add("nodecrypt_par", true).AsString();
		if( nodecrypt_par.empty() ) 
			nodecrypt_par = "Settings/dcrpt_f", 
			p_meta->item_add("nodecrypt_par", true).FromString(nodecrypt_par.c_str()); 

		// Если флаги непустые - разбираем их.
		if( unsigned nodecrypt = p_settings->item_add(nodecrypt_par.c_str(), true).AsUInt() )
		{
			ISettings* p_meta_flags = p_meta->item_add("nodecrypt_flags", false).AsSettings();
			unsigned flag = 1;
			for(int Nbits = std::numeric_limits<unsigned>::digits; Nbits-- > 0; flag <<= 1 )
			{
				if( !(nodecrypt & flag) ) continue; 

				std::string flag_key = "flag" + to_string(flag); 
				try{ 
					std::string flag_val = p_meta_flags->item(flag_key.c_str()).AsString();
					// ищем значение в общем дереве и устанавливаем ему значение шифрования в false
					p_settings->item(flag_val.c_str()).encoded(false); 
				}
				catch(ProLoyalty::SettingNotFound&){;}
			}
		}	
	}
	//-------------------------------------------------------------------------------
	ISettings*	LoadXMLSettings(Settings* p_settings, const char* file_nm, 
								IStringCrypter* p_crypter)
	{
		tinyxml2::XMLDocument doc;

		if( !file_nm || !*file_nm )  
			throw CannotLoadSettings("LoadXMLSettings error: file_nm is empty!");
		
		if( tinyxml2::XML_SUCCESS != doc.Parse(file_nm) )
			if( tinyxml2::XML_SUCCESS != doc.LoadFile(file_nm) )
			{
				ostringstream oss;
				oss << "LoadXMLSettings doc.LoadFile(" << file_nm << ") XML error: " << doc.ErrorID(); 
				if(doc.ErrorName()) oss << ", text: '" << doc.ErrorName() << "'";
				throw CannotLoadSettings(oss.str());
			}
		
		if( doc.RootElement() )
		{
			// Разбор без дешифрования! 
			ParseXMLToSettings(p_settings, doc.RootElement()->FirstChildElement(), NULL);

			// После разбора дерева обеспечиваем проход по дереву для дешифрования. 
			SetNoDecryptFlags(p_settings);

			// И дешифруем настройки
			DecryptSettings(p_settings, p_crypter);
		}

		return p_settings;
	}
	//-------------------------------------------------------------------------------
	struct ParseIniHolder
	{ 
		CSimpleIniCaseA* m_ini; 
		Settings* m_settings; 

		ParseIniHolder() 
			: m_ini(NULL), m_settings(NULL)	{}
		ParseIniHolder(CSimpleIniCaseA* ini, Settings* settings) 
			: m_ini(ini), m_settings(settings)	{}		
	};
	//-------------------------------------------------------------------------------
	// Parsing of nested kes as SubSection1/SubKey1=Value as nested NodeSetting
	void  parse_ini_key(const string& key_nm, const string& key_val, Settings* parent_settings)
	{
		string::size_type i = key_nm.find('/'); 
		if( string::npos != i )
		{	// it is not a dippest level - dive dipper
			string node_nm = key_nm.substr(0, i);
			auto p = find_if(begin(parent_settings->settings()), end(parent_settings->settings()),
							 bind(Setting_find_name, _1, node_nm.c_str()));

			Setting* node_setting = parent_settings->settings().end() != p ? p->get() : 
								    new NodeSetting(parent_settings, node_nm.c_str()); 
			parse_ini_key(key_nm.substr(i + 1), key_val, node_setting->ToSettings() );
			return;
		}
		new ValSetting(parent_settings, key_nm.c_str(), key_val.c_str());
	}
	//-------------------------------------------------------------------------------
	void  parse_ini_key(CSimpleIniCaseA::Entry const& key, ParseIniHolder* ini_holder)
	{
		Setting* settingsNode = ini_holder->m_settings->nodeOwner();
		string sect_nm = settingsNode->Name();
		string key_val = ini_holder->m_ini->GetValue(sect_nm.c_str(), key.pItem, NULL, NULL);
		parse_ini_key(key.pItem, key_val, ini_holder->m_settings);
	}
	//-------------------------------------------------------------------------------
	void  parse_ini_section(const CSimpleIniCaseA::Entry sect, ParseIniHolder* ini_holder)
	{
		Setting* node_setting = new NodeSetting(ini_holder->m_settings, sect.pItem); 
		
		CSimpleIniCaseA::TNamesDepend a_keys;
		ini_holder->m_ini->GetAllKeys(sect.pItem, a_keys);
		a_keys.sort(CSimpleIniCaseA::Entry::LoadOrder());
		ParseIniHolder lcl_ini_holder(ini_holder->m_ini, node_setting->ToSettings()); 
		for_each(a_keys.begin(), a_keys.end(), 
			[&lcl_ini_holder](CSimpleIniCaseA::Entry const& key){ parse_ini_key(key, &lcl_ini_holder); }	
		);
	}
	//-------------------------------------------------------------------------------
	ISettings*	LoadINISettings(Settings* p_settings, const char* file_nm)
	{
		const bool  	a_bIsUtf8 = false, a_bMultiKey = false, a_bMultiLine = false; 

		CSimpleIniCaseA  ini(a_bIsUtf8, a_bMultiKey, a_bMultiLine);
		ini.LoadFile(file_nm);
		
		CSimpleIniCaseA::TNamesDepend a_names;
		ini.GetAllSections(a_names);
		a_names.sort(CSimpleIniCaseA::Entry::LoadOrder());
		ParseIniHolder ini_holder(&ini, p_settings);
		for_each(a_names.begin(), a_names.end(), 
			 bind(parse_ini_section, _1, &ini_holder) );
		
		return p_settings;
	}
	//-------------------------------------------------------------------------------
	struct SaveIniHolder
	{ 
		CSimpleIniCaseA* m_ini; 
		IStringCrypter*  m_crypter;

		SaveIniHolder() 
			: m_ini(NULL), m_crypter(NULL)	{}
		
		SaveIniHolder(CSimpleIniCaseA* ini, IStringCrypter* p_crypter) 
			: m_ini(ini), m_crypter(p_crypter)	{}		
	};
	//-------------------------------------------------------------------------------
	void	save_Setting_to_INI(Setting::Ptr_t& setting, SaveIniHolder* ini_holder)
	{
		if( Setting::typeNode != setting->getType() )
		{
			// имя секции - первое имя в полном имени
			// имя ключа - все остальное после имени секции в полном имени
			string section = setting->FullName();		
			string::size_type pos = section.find_first_of('/');
			string nm = string::npos == pos ? section : section.substr(pos + 1);
			if( string::npos != pos )
				section = section.substr(0, pos);
			
			if( boolTrue == setting->Owner()->keysHaveEncryptName() )
				nm = ini_holder->m_crypter->encrypt_string(nm.c_str());
			
			ini_holder->m_ini->SetValue(section.c_str(), 
				nm.c_str(), 
				boolTrue == setting->Encoded() || 
				(boolFalse != setting->Encoded() &&  
				 boolTrue == setting->Owner()->valuesHaveEncryptName()) ? 
					ini_holder->m_crypter->encrypt_string(setting->AsString().c_str()).c_str() 
					: setting->AsString().c_str() 
			);
		}
		else 
		{
			// создадим пустую секцию
			if( !setting->Parent() )
				ini_holder->m_ini->SetValue(setting->Name().c_str(), NULL, NULL);		

			for_each(setting->ToSettings()->settings().begin(), 
					 setting->ToSettings()->settings().end(), 
					 bind(save_Setting_to_INI, _1, ini_holder)
				);	
		}
	}
	//-------------------------------------------------------------------------------
	void	SaveINISettings(Settings const& settings, const char* dest_addr, IStringCrypter* p_crypter)
	{
		const bool  	a_bIsUtf8 = false, a_bMultiKey = false, a_bMultiLine = false; 
		
		// сохраняем только с верхнего уровня
		if( settings.nodeOwner() ) return;

		CSimpleIniCaseA  ini(a_bIsUtf8, a_bMultiKey, a_bMultiLine);
		SaveIniHolder    ini_holder(&ini, p_crypter);

		// Цикл по элементам, те, которые имеют тип Узел - будут секцией
		// Если элемент не узел - будет жить в пустой секции
		for_each(settings.settings().begin(), settings.settings().end(), 
				 bind(save_Setting_to_INI, _1, &ini_holder)
				);		

		ini.SaveFile(dest_addr);		
	}
	//-------------------------------------------------------------------------------
	struct SaveXMLHolder
	{
		SaveXMLHolder() 
			: m_doc(NULL), m_curr_el(NULL), m_crypter(NULL) {}
		SaveXMLHolder(tinyxml2::XMLDocument* doc, tinyxml2::XMLElement* curr_el, 
					  IStringCrypter* p_crypter) 
			: m_doc(doc), m_curr_el(curr_el), m_crypter(p_crypter)  {}

		tinyxml2::XMLDocument* m_doc;
		tinyxml2::XMLElement*  m_curr_el;
		IStringCrypter*		   m_crypter;
	};
	//-------------------------------------------------------------------------------
	void	save_Setting_to_xml(Setting::Ptr_t& p_setting, SaveXMLHolder* p_xml_info)
	{
		tinyxml2::XMLElement* p_el = p_xml_info->m_doc->NewElement(p_setting->Name().c_str());
		p_xml_info->m_curr_el->InsertEndChild(p_el);
		Settings* p_settings = p_setting->ToSettings();
		if( !p_settings )
		{ 
			if(boolEmpty != p_setting->Encoded()) 
				p_el->SetAttribute("_enc", TriStateBool_to_str(p_setting->Encoded()));
			
			p_el->SetText(			
				boolTrue == p_setting->Encoded() || 
				(boolFalse != p_setting->Encoded() &&  
				 boolTrue == p_setting->Owner()->valuesHaveEncryptName()) ? 
					p_xml_info->m_crypter->encrypt_string(p_setting->AsString().c_str()).c_str() 
					: p_setting->AsString().c_str()				
			);
			return;
		}
		
		if(boolEmpty != p_settings->keysHaveEncryptName()) 
			p_el->SetAttribute("_enc_keys", TriStateBool_to_str(p_settings->keysHaveEncryptName()));
		if(boolEmpty != p_settings->valuesHaveEncryptName()) 
			p_el->SetAttribute("_enc_vals", TriStateBool_to_str(p_settings->valuesHaveEncryptName()));
		
		if( 0 == p_settings->size() )
			p_el->SetAttribute("_tp", "N");

		SaveXMLHolder xml_holder(p_xml_info->m_doc, p_el, p_xml_info->m_crypter);
		for_each(p_settings->settings().begin(), p_settings->settings().end(), 
				 bind(save_Setting_to_xml, _1, &xml_holder)
				);		
	}
	//-------------------------------------------------------------------------------
	void	SaveXMLSettings(Settings const& settings, const char* dest_addr, IStringCrypter* p_crypter)
	{
		tinyxml2::XMLDocument doc;
		doc.InsertEndChild(doc.NewDeclaration());
		doc.InsertEndChild(doc.NewElement("AppSettings"));
		
		SaveXMLHolder xml_holder(&doc, doc.RootElement(), p_crypter);
		for_each(settings.settings().begin(), settings.settings().end(), 
				 bind(save_Setting_to_xml, _1, &xml_holder)
				);		
		doc.SaveFile(dest_addr);
	}
	//-------------------------------------------------------------------------------
	// необходимо обработать новое дерево настроек по данным текущего дерева, 
	// так как предполагается, что в текущем дереве содержатся метданные из атрибутов XML 
	// бежим по новому дереву и на каждом уровне ищем элемент с таким же именем, при этом учитываем, что 
	// возможно шифрование имен элементов, если был атрибут _keys_enc=true в объекте Settings.
	// 
	// если не находим - вырезаем новый элемент из нового дерева и перевязываем в текущее. 
	// если находим - проверяем, чтобы типы элементов совпадали. Если типы не совпадают, 
	// удаляем элемент из текущего дерева и вставляем из нового. 
	// Если типы совпадают, если элементы являются значениями - производим копирование значения с учетом атрибутов, 
	// при этом возможно что значение элемента зашифровано и его надо расшифровать перед копированием, это 
	// лучше сделать путем передачи стратегии шифрования элементу типа Значение при чтении его из XML метаданных.
	// Если элементы являются Узлами - то к ним рекурсивно применяется вышепописанный алгоритм.
	//-------------------------------------------------------------------------------
	void   AddSettingsToTemplate(Settings& templ_settings, Settings* data_settings, IStringCrypter* p_crypter)
	{
		if( &templ_settings == data_settings ) return;		
		
		while( data_settings && data_settings->size() > 0 )
		{
			Setting& data_setting = static_cast<Setting&>(data_settings->at(0));					
			Setting* templ_setting = NULL; 
			try
			{
				// TODO учесть перекодировку имени настройки				
				templ_setting = &static_cast<Setting&>(templ_settings.item(data_setting.Name().c_str()));
			}
			catch(SettingNotFound& )
			{
				// не нашли - перецепляем 
				data_setting.Owner(&templ_settings, p_crypter);
				
				// TODO учесть перекодировку имени настройки и значения				
				continue;	
			}
			
			// типы не совпадают - считаем, что data_setting имеет приоритет, переносим его в текущие настройки
			if( data_setting.getType() != templ_setting->getType() )
			{
				templ_setting->Owner(NULL, p_crypter);
				delete templ_setting;
				data_setting.Owner(&templ_settings, p_crypter);
				continue;
			}
			
			// типы совпадают 
			// если это узлы - рекурсивно применить к ним эту функцию
			// TODO не забыть про флаги с атрибутами
			if( Setting::typeNode == data_setting.getType() )
			{
				AddSettingsToTemplate(*templ_setting->ToSettings(), data_setting.ToSettings(), p_crypter);
			}
			// иначе скопировать значение из data_setting в *templ_setting
			else
			{
				//templ_setting->	Encoded( templ_setting->Encoded() || data_setting.Encoded() );
				string sVal = data_setting.AsString();
				if( p_crypter && boolTrue == templ_setting->Encoded() && 
					boolEmpty == data_setting.Encoded() 
				)
				{
					sVal = p_crypter->decrypt_string(data_setting.AsString().c_str());
				}
				templ_setting->FromString(sVal.c_str());
			}

			// обработали узел data_setting: 
			data_setting.Owner(NULL, NULL);	// отвяжем...
			delete &data_setting;       // и удалим его 
		}
	}
	//-------------------------------------------------------------------------------
	void	Settings::load(SettingsSrcType source_type, const char* source_addr)
	{
		nodeOwner(NULL);

		IStringCrypter::Ptr_t crypto(IStringCrypter::Create(encoded() ? c_crypter_name : ""));

		auto ps = make_unique<Settings>();
		switch(source_type)
		{
		default: break;
		case SettingsSrcIni: LoadINISettings(ps.get(), source_addr); break;
		case SettingsSrcXML: LoadXMLSettings(ps.get(), source_addr, crypto.get()); break;
		}
		
		// без дешифрования
		AddSettingsToTemplate(*this, ps.get(), NULL); 

		// проверяем и ставим флаги дешифрования
		SetNoDecryptFlags(this);

		// И дешифруем настройки
		DecryptSettings(this, crypto.get());
	}
	//-------------------------------------------------------------------------------
	void	Settings::save(SettingsSrcType dest_type, const char* dest_addr) const 
	{
		IStringCrypter::Ptr_t  crypto(IStringCrypter::Create(encoded() ? c_crypter_name : ""));

		switch(dest_type)
		{
		default: break;
		case SettingsSrcIni: SaveINISettings(*this, dest_addr, crypto.get()); break;
		case SettingsSrcXML: SaveXMLSettings(*this, dest_addr, crypto.get()); break;
		}
	}
	//-------------------------------------------------------------------------------
	ISettings*	CreateSettings(const char* settings_info)
	{
		IStringCrypter::Ptr_t crypto(IStringCrypter::Create(c_crypter_name));
		auto ps = make_unique<Settings>();
		if( settings_info && *settings_info )
			LoadXMLSettings(ps.get(), settings_info, crypto.get());
		return ps.release();
	}
	//-------------------------------------------------------------------------------
	ISettings*	TestCteateSettings()
	{
		auto ps = make_unique<Settings>();
		
		Setting* sect0 = new NodeSetting(ps.get(), "Settings");
		Setting* val0 = new ValSetting(sect0->ToSettings(), "conn_timeout");
		val0->FromInt(60000);
		cout << "val0->AsString(): " <<	val0->AsString() << endl;
		
		val0 = new ValSetting(sect0->ToSettings(), "passw", "PASSW");
		cout << "val0->AsString(): " <<	val0->AsString() << endl;

		sect0 = new NodeSetting(ps.get(),  "Limits");
		sect0 = new NodeSetting(sect0->ToSettings(), "Limit0");
		val0 = new ValSetting(sect0->ToSettings(), "defdisc", 5.0);
		cout << "val0->AsString(): " <<	val0->AsDouble() << endl;
				
		return ps.release();
	}
	//-------------------------------------------------------------------------------



} //namespace Seredina



