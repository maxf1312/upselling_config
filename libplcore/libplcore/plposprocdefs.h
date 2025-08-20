#pragma once 

#ifndef __PLPOSPROCDEFS_H__
#define __PLPOSPROCDEFS_H__

#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif


///-----------------------------------------------------------------------------
///
/// Константы, используемые для определения строковых буферов
///
///-----------------------------------------------------------------------------
enum SEREDINA_CONST { 
	SEREDINA_MAXSTRLEN = 255, 
	SEREDINA_CARDNUMLEN = 30, 
	SEREDINA_CHQNUMLEN = 30, 
	SEREDINA_RRNLEN = 95, 
	SEREDINA_ARTLEN = 40, 
	SEREDINA_ARTNMLEN = 255, 
	SEREDINA_CATLEN = 20, 
	SEREDINA_NMLEN = 30, 
	SEREDINA_EMAILLEN = 60,
	SEREDINA_PHONELEN = 20, 
	SEREDINA_GUIDLEN = 39,
	SEREDINA_POSTALLEN = 10,
	SEREDINA_PASSWORDLEN = 39,
	SEREDINA_ADDR1LEN = 40,
	SEREDINA_HOMELEN = 4,
	SEREDINA_PARTNERCATLEN = 30,
	SEREDINA_MAXPARTNERCATCNT = 3, 
	SEREDINA_NAMELEN = 50,
	SEREDINA_ATTRNAMLEN = 255,	
	SEREDINA_ATTRVALLEN = 255,	
	SEREDINA_ADDINFOLEN = 200, 
	SEREDINA_MSGLEN = 1000, 
	SEREDINA_RESMSGLEN = 511, 
	SEREDINA_COMMENTLEN = 100,
    SEREDINA_MAXEXTATTRCOUNT = 10,
} ;

///-----------------------------------------------------------------------------
///
/// Коды ошибок. 
/// Дополнительно процессинг возвращает свои коды ошибок, описанные в Приложении 1.
///
///-----------------------------------------------------------------------------
enum  SEREDINA_ERRORS { 
	/// @SEREDINA_ERR_OK - успешное выполнение
	SEREDINA_ERR_OK = 0, 
	/// @SEREDINA_ERR_NOTIMPL - Функция не реализована
	SEREDINA_ERR_NOTIMPL = -20,
	/// @SEREDINA_ERR_INVARG - Неверный аргумент функции
	SEREDINA_ERR_INVARG = -21,
	/// @SEREDINA_ERR_APPERR - Общая ошибка приложения
	SEREDINA_ERR_APPERR = -22,
	/// @SEREDINA_ERR_INVHANDLE - Неверный дескриптор процессинга
	SEREDINA_ERR_INVHANDLE = -23,
	/// @SEREDINA_ERR_NOHANDLER - Нет обработчика запроса
	SEREDINA_ERR_NOHANDLER = -24,
	/// @SEREDINA_ERR_BADINDEX - Неверный индекс в коллекции
	SEREDINA_ERR_BADINDEX = -25,
	/// @SEREDINA_ERR_OPERCOUNTLIMOVER - Превышен лимит на кол-во операций
	SEREDINA_ERR_OPERCOUNTLIMOVER = -26,
	/// @SEREDINA_ERR_OPERSUMMLIMOVER - Превышен лимит на сумму операции
	SEREDINA_ERR_OPERSUMMLIMOVER = -27,
	/// @SEREDINA_ERR_DBERROR - Ошибка работы с БД
	SEREDINA_ERR_DBERROR = -28,
	/// @SEREDINA_ERR_MODLOAD - Ошибка загрузки модуля
	SEREDINA_ERR_MODLOAD = -29,
	/// @SEREDINA_ERR_BADFORMAT - Ошибка формата сообщения
	SEREDINA_ERR_BADFORMAT = -30,
	/// @SEREDINA_ERR_LK_NOAUTH - Ошибка авторизации ЛК
	SEREDINA_ERR_LK_NOAUTH = -31,
	/// @SEREDINA_ERR_LK_ERR - Ошибка ЛК общая
	SEREDINA_ERR_LK_ERR = -32,
	/// @SEREDINA_ERR_NOAUTH - Ошибка авторизации 
	SEREDINA_ERR_NOAUTH = -33,
	/// @SEREDINA_ERR_CARDNOTFOUND - Карта не найдена
	SEREDINA_ERR_CARDNOTFOUND = -34,
	/// @SEREDINA_ERR_LK_REGNOTCOMPLETE - Регистрация анкеты не завершена, требуется код подтверждения
	SEREDINA_ERR_LK_REGNOTCOMPLETE = -35,
	/// @SEREDINA_ERR_CONTACTNOTFOUND - Контакт не найден
	SEREDINA_ERR_CONTACTNOTFOUND = -36,
	/// @SEREDINA_ERR_OFFERSNOTFOUND - Не найдены товарные предлоажения
	SEREDINA_ERR_OFFERSNOTFOUND = -37,


	/// @SEREDINA_ERR_BADCARDSTAT - Статус карты некорректный - заблокирована
	SEREDINA_ERR_BADCARDSTAT = -14,
	/// @SEREDINA_ERR_BADCARDNUM - Номер карты пустой или некорректный
	SEREDINA_ERR_BADCARDNUM = -13,
	/// @SEREDINA_ERR_BADCARDRANGE - Карта попадает в запрещенный к использованию диапазон
	SEREDINA_ERR_BADCARDRANGE = -11,
	/// @SEREDINA_ERR_OFFLINE - Связь с процессинговым центром отсутствует
	SEREDINA_ERR_OFFLINE = -2,

};

///-----------------------------------------------------------------------------
///
/// Тип чека. 
/// @seredina_Fiscal - фискальный чек, приводит к изменению бонусного баланса
/// @seredina_Soft   - мягкий чек, обеспечивает выполнение всех правил и проверок без 
///                   изменения баланса.
///
///-----------------------------------------------------------------------------
enum seredina_cheque_type_t { seredina_Fiscal, seredina_Soft };

///-----------------------------------------------------------------------------
/// Тип запроса. 
/// @seredina_req_Balance  - запрос баланс
/// @seredina_req_Discount - запрос скидки
/// @seredina_req_Cheque   - чек
/// @seredina_req_Offer    - акции и предложения
/// @seredina_req_SMSRequest - запрос СМС подтверждения для процессинга
/// @seredina_req_Bonus    - начисление или списание ручного бонуса
///
///-----------------------------------------------------------------------------
enum seredina_req_type_t {	seredina_req_Balance, 
							seredina_req_Discount, 
							seredina_req_Cheque, 
							seredina_req_Offer, 
							seredina_req_SMSRequest,
							seredina_req_ChargeBonus };
 	
///-----------------------------------------------------------------------------
/// Тип операции. 
/// @seredina_oper_Sale - Продажа
/// @seredina_oper_Return - Возврат
/// @seredina_oper_Rollback - Откат
///-----------------------------------------------------------------------------
enum seredina_oper_type_t { seredina_oper_Sale, seredina_oper_Return, seredina_oper_Rollback };

///-----------------------------------------------------------------------------
/// Тип платежа 
/// @seredina_pay_Money - Наличка 
/// @seredina_pay_Bonus - Баллы
///-----------------------------------------------------------------------------
enum seredina_pay_type_t { seredina_pay_Money, seredina_pay_Bonus};

///-----------------------------------------------------------------------------
/// Формат RRN 
/// @seredina_rrnfmt_None - Неизвестный
/// @seredina_rrnfmt_Long - длинный,
/// @seredina_rrnfmt_Short1	- короткий 1,
///	@seredina_rrnfmt_Short2	- короткий 2,
///	@seredina_rrnfmt_Short3 - короткий 3
///-----------------------------------------------------------------------------
enum seredina_rrnfmt_type_t 
{ seredina_rrnfmt_None, seredina_rrnfmt_Long, seredina_rrnfmt_Short1,
  seredina_rrnfmt_Short2, seredina_rrnfmt_Short3
};

///-----------------------------------------------------------------------------
/// Тип операции для списка покупок по карте 
/// @seredina_sale_opertype_none	 - Нет данных
/// @seredina_sale_opertype_purchase - Продажа
/// @seredina_sale_opertype_return	 - Возврат
///-----------------------------------------------------------------------------
enum seredina_sale_opertype_t 
{ 
	seredina_sale_opertype_none, 
	seredina_sale_opertype_purchase, 
	seredina_sale_opertype_return
};

///-----------------------------------------------------------------------------
/// Тип операции для списка бонусов 
/// @seredina_bonus_opertype_none	 - Нет данных
/// @seredina_bonus_opertype_purchase - Продажа
/// @seredina_bonus_opertype_return	 - Возврат
///-----------------------------------------------------------------------------
enum seredina_bonus_opertype_t 
{ 
	seredina_bonus_opertype_none, 
	seredina_bonus_opertype_purchase, 
	seredina_bonus_opertype_return
};

///-----------------------------------------------------------------------------
/// Тип статуса карт
/// @seredina_cardstatus_none	 - Нет данных
/// @seredina_cardstatus_new	 - Новая
/// @seredina_cardstatus_active	 - Активная
/// @seredina_cardstatus_blocked - Заблокированная
/// @seredina_cardstatus_reserved0 - Код зарезервирован
/// @seredina_cardstatus_closed   - Закрыта
/// @seredina_cardstatus_complete - Завершена
///-----------------------------------------------------------------------------
enum seredina_cardstatus_type_t 
{ 
    seredina_cardstatus_none,
    seredina_cardstatus_new,
    seredina_cardstatus_active, 
    seredina_cardstatus_blocked,
    seredina_cardstatus_reserved0,
    seredina_cardstatus_closed,
    seredina_cardstatus_complete
};

///-----------------------------------------------------------------------------
/// Коды наименований полей
/// @proloy_field_none                  - неизвестно    
/// @proloy_field_resp_cheque_message   - поле сообщение чека в ответе 
/// @proloy_field_resp_cashier_message  - поле сообщение кассиру в ответе
/// @proloy_field_resp_personal_message - поле персональное сообщение в ответе
///-----------------------------------------------------------------------------

enum proloy_field_code_t{
    proloy_field_none = 0,
    proloy_field_resp_cheque_message,
    proloy_field_resp_cashier_message,
    proloy_field_resp_personal_message
};

///-----------------------------------------------------------------------------
/// Типы данных 
///-----------------------------------------------------------------------------
typedef unsigned			seredina_bool_t;
typedef double				seredina_datetime;
typedef seredina_datetime	seredina_date;
typedef long long			seredina_tran_id_t;

const seredina_bool_t seredina_bool_true = 1;
const seredina_bool_t seredina_bool_false = 0;

enum seredina_tribool_t 
{ 
    seredina_tribool_intermediate = 0, seredina_tribool_false, seredina_tribool_true = 2
};

///-----------------------------------------------------------------------------
/// Обработка товарных предложений ДоПродажника
///-----------------------------------------------------------------------------

    /// @proloy_gender_t - перечисление для поля Пол
    enum proloy_gender_t
    {
        proloy_gender_none,
        proloy_gender_female,
        proloy_gender_male           
    };

    /// @proloy_family_status_t - перечисление для поля Семейное положение
    enum proloy_family_status_t
    {
        proloy_family_status_none,
        proloy_family_status_single,
        proloy_family_status_married,
        proloy_family_status_divorced
    };

    /// @proloy_offer_feedback_code_t - перечисление для кода обратной связи на предложение покупателю
    enum proloy_offer_feedback_code_t
    {
        proloy_offer_feedback_code_none = 0,
        proloy_offer_feedback_code_yes  = 1,
        proloy_offer_feedback_code_no   = 2,
        proloy_offer_feedback_code_irrelevant = 4
    };

    enum PROLOY_CONST {
        PROLOY_MAX_EXT_PARAMS = 10,
        PROLOY_MAX_MAIN_OFFERS = 1
    };

#pragma pack(push, 1)


///-----------------------------------------------------------------------------
/// Структура  @seredina_result_t
/// Содержит результат выполнения операции
///-----------------------------------------------------------------------------
typedef struct tag_seredina_result 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_result_t) 
			size_t				size_of_struct;
			
			/// @return_code  - Код возврата. 0 при успехе, иначе или код из SEREDINA_ERRORS, 
			/// или код от процессинга
			int					return_code;			
			
			/// @return_msg - Текст сообщения об ошибке.
			wchar_t				return_msg[SEREDINA_RESMSGLEN + 1];
			
			/// @id_transaction - идентификатор транзакции
			seredina_tran_id_t	id_transaction;

			/// @processed_dt - дата и время обработки операции
			time_t				processed_dt;	

			/// @is_offline   - транзакция проводилась offline, либо произошел разрыв связи
			bool				is_offline;	
		} seredina_result_t;

///-----------------------------------------------------------------------------
/// Структура seredina_balance_result_t
/// Содержит результат выполнения операции "Запрос баланса"
///-----------------------------------------------------------------------------
typedef struct tag_seredina_balance_result 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_balance_result_t) 
			size_t			size_of_struct;
			
			double			balance;
			double			discount;
			seredina_bool_t	contact_is_correct;
			seredina_bool_t	phone_exists;
			wchar_t			full_name[SEREDINA_MAXSTRLEN + 1];
			wchar_t			first_name[SEREDINA_NMLEN + 1];
			wchar_t			last_name[SEREDINA_NMLEN + 1];
			wchar_t			middle_name[SEREDINA_NMLEN + 1];
			wchar_t			phone[SEREDINA_PHONELEN + 1];
			wchar_t			email[SEREDINA_EMAILLEN + 1];
			int				age;
			seredina_date	birthday;
		} seredina_balance_result_t;

///-----------------------------------------------------------------------------
/// Структура  @seredina_extattr_t
/// Содержит универсальный расширенный атрибут
///-----------------------------------------------------------------------------
typedef struct tag_seredina_extattr_t 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_extattr_t) 
			size_t			size_of_struct;
			wchar_t		 	name[SEREDINA_ATTRNAMLEN + 1];
			wchar_t		 	value[SEREDINA_ATTRNAMLEN + 1];
		} seredina_extattr_t;

///-----------------------------------------------------------------------------
/// Структура seredina_balance_result2_t
/// Содержит дополнительные поля результата выполнения операции "Запрос баланса"
/// Старую структуру не трогаем - т.к. это двоичный интерфейс
///-----------------------------------------------------------------------------
typedef struct tag_seredina_balance_result2 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_balance_result2_t) 
			size_t			size_of_struct;
			
			double			balance;
			double			discount;
			seredina_bool_t	contact_is_correct;
			seredina_bool_t	phone_exists;
			wchar_t			full_name[SEREDINA_MAXSTRLEN + 1];
			wchar_t			first_name[SEREDINA_NMLEN + 1];
			wchar_t			last_name[SEREDINA_NMLEN + 1];
			wchar_t			middle_name[SEREDINA_NMLEN + 1];
			wchar_t			phone[SEREDINA_PHONELEN + 1];
			wchar_t			email[SEREDINA_EMAILLEN + 1];
			int				age;
			seredina_date	birthday;
			// часть, связанная с версией 2
			double			full_balance;
			wchar_t			card_number[SEREDINA_CARDNUMLEN + 1];
			wchar_t			contact_id[SEREDINA_GUIDLEN + 1];
			wchar_t			add_info[SEREDINA_ADDINFOLEN + 1];
			double			card_summ;
			double			card_summ_discounted;

			wchar_t			cashier_message[SEREDINA_MSGLEN + 1];
			wchar_t			cheque_message[SEREDINA_MSGLEN + 1];
			wchar_t			personal_message[SEREDINA_MSGLEN + 1];

			// TODO избавиться от сообщений с суффиксом 2 - подумать над введением коллекции строк
			//wchar_t			cashier_message2[SEREDINA_MSGLEN + 1];
			//wchar_t			cheque_message2[SEREDINA_MSGLEN + 1];
			//wchar_t			personal_message2[SEREDINA_MSGLEN + 1];

			double			status_balance;
			double			full_status_balance;

            seredina_extattr_t ext_attrs[SEREDINA_MAXEXTATTRCOUNT];
		} seredina_balance_result2_t;


typedef struct tag_seredina_cheque_result 
		{  
			size_t					size_of_struct;
			double					summ;
			double					discount;
			double					summ_discounted;
			double					balance;
			double					charged_bonus;
			double					discounted_bonus;
			double					available_payment;	
			wchar_t					cheque_number[SEREDINA_CHQNUMLEN + 1];
			wchar_t					rrn[SEREDINA_RRNLEN + 1];
			seredina_cheque_type_t	cheque_type;
			seredina_req_type_t		req_type;
			seredina_oper_type_t	oper_type;
			seredina_pay_type_t		pay_type;
			double					curr_discount;			// скидка в валюте, не процент
			double					charged_status_bonus;
			double					discounted_status_bonus;
		} seredina_cheque_result_t;

typedef struct tag_seredina_cheque_item 
		{  
			size_t					size_of_struct;
			int						position_number;
			wchar_t		 			article[SEREDINA_ARTLEN + 1];
			wchar_t		 			article_name[SEREDINA_ARTNMLEN + 1];
			wchar_t		 			category[SEREDINA_CATLEN + 1];
			double					price;
			double                  quantity;
			double                  summ; 
			double                  discount;
			double                  summ_discounted;
			double                  available_payment;
			double					charged_bonus;
			double					discounted_bonus;
			double					curr_discount;			// скидка в валюте, не процент
			double					charged_status_bonus;
			double					discounted_status_bonus;
		} seredina_cheque_item_t;

///-----------------------------------------------------------------------------
/// Структура  @seredina_request_t
/// Содержит универсальный запрос для выполнения операции
///-----------------------------------------------------------------------------
typedef struct tag_seredina_request
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_request_t) 
			size_t				size_of_struct;

			/// @req_type - Тип запроса 
			seredina_req_type_t req_type;

			/// @chq_type - Тип чека 
			seredina_cheque_type_t chq_type;
 	
			/// @oper_type - Тип операции
			seredina_oper_type_t oper_type;

			/// @pay_type - Тип платежа
			seredina_pay_type_t pay_type;

			/// @rrn_fmt - Тип формата RRN
			seredina_rrnfmt_type_t rrn_fmt;

			/// @ org_partner - организация-партнер, если NULL - из настроек
			const wchar_t* org_partner; 

			/// @ organization - партнер, если NULL - из настроек
			const wchar_t* organization; 
			
			/// @ bunit - магазин, если NULL - из настроек
			const wchar_t* bunit; 
			
			/// @ pos - терминал, если NULL - из настроек
			const wchar_t* pos; 
			
			/// @card_number - номерк карты
			const wchar_t* card_number; 
			
			/// @datetime_dt - дата и время чека, либо дата запроса баланса
			time_t				datetime_dt;
			
			/// @cheque_number - номер чека, если NULL или L"" - генерируется автоматом
			const wchar_t*		cheque_number;

			/// @request_id - номер запроса, если NULL или L"" - генерируется автоинкрементом
			const wchar_t*		request_id;
			
			/// @id_transaction - идентификатор транзакции
			seredina_tran_id_t	id_transaction;
			
			// @rrn - RRN операции для отката или возврата
			const wchar_t*		rrn; 

			double				summ;
			double				discount;
			double				bonus_to_count;
			double				paid_by_bonus;
			
			// Если seredina_true, то НЕ добавлять случайный шум к номеру чека
			seredina_bool_t		not_add_noise_to_chq_num;	

			const wchar_t*		phone_number;
			const wchar_t*		validate_code;
			
		} seredina_request_t;

///-----------------------------------------------------------------------------
/// Структура  @seredina_response_t
/// Содержит универсальный ответ о выполнении операции
///-----------------------------------------------------------------------------
typedef struct tag_seredina_response
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_response_t) 
			size_t				size_of_struct;

			/// @base_result - базовый результат
			seredina_result_t	base_result;		
			
			/// @balance_result - результат баланса
			seredina_balance_result_t*	balance_result;	

			/// @cheque_result - результат чека
			seredina_cheque_result_t*	cheque_result;		

        } seredina_response_t;

///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_auth_result_t
/// Содержит результат выполнения операции авторизации или запроса данных о сессии
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_auth_result 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_lk_auth_result_t) 
			size_t				size_of_struct;
			
			/// @base_result - базовый результат
			seredina_result_t	base_result;		
			
			/// @session_id - GUID сессии.
			wchar_t				session_id[SEREDINA_GUIDLEN + 1];
		} seredina_lk_auth_result_t;
		
///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_change_user_result_t
/// Содержит результат выполнения операции изменения контактных данных
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_change_user_result 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_lk_change_user_result_t) 
			size_t				size_of_struct;
			
			/// @base_result - базовый результат
			seredina_result_t	base_result;		
			
			/// @contact_id - GUID контактных данных.
			wchar_t				contact_id[SEREDINA_GUIDLEN + 1];

			/// @local_id  - ИД записи в локальной БД, если был Offline 
			int					local_id;			

			/// @password - начальный пароль после регистрации, если непустой.
			wchar_t				password[SEREDINA_PASSWORDLEN + 1];

			/// @card_number - номер карты.
			wchar_t				card_number[SEREDINA_CARDNUMLEN + 1];
		} seredina_lk_change_user_result_t;

///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_validate_card_result_t
/// Содержит результат выполнения операции проверки карты
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_validate_card_result 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_lk_validate_card_result_t) 
			size_t				size_of_struct;
			
			/// @base_result - базовый результат
			seredina_result_t	base_result;		
			
			/// @contact_id - GUID карты.
			wchar_t				card_id[SEREDINA_GUIDLEN + 1];
			
		} seredina_lk_validate_card_result_t;
		
///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_sale_data_t
/// Содержит результат об одной покупке
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_sale_data 
		{  
			/// @datetime - дата и время покупки.
			seredina_datetime	datetime;          
			/// @cheque_number - номер чека.
			wchar_t				cheque_number[SEREDINA_CHQNUMLEN + 1];
			/// @summ - сумма покупки.
			double				summ;          
			/// @paid_by_bonus - оплачено баллами.
			double				paid_by_bonus;          
			/// @bonus - начислено баллов.
			double				bonus;   
			/// @тип операции
			seredina_sale_opertype_t oper_type;
			/// @partner_id - GUID партнера продажи.
			wchar_t				partner_id[SEREDINA_GUIDLEN + 1];
			/// @partner_name - Имя партнера продажи.
			wchar_t				partner_name[SEREDINA_NAMELEN + 1];
			/// @buint_id - GUID магазина продажи.
			wchar_t				bunit_id[SEREDINA_GUIDLEN + 1];
			/// @buint_name - Имя магазина продажи.
			wchar_t				bunit_name[SEREDINA_NAMELEN + 1];

			/// @card_id - GUID карты.
			wchar_t				card_id[SEREDINA_GUIDLEN + 1];
			/// @card_number - номер карты.
			wchar_t				card_number[SEREDINA_CARDNUMLEN + 1];

			/// @cheque_id ID чека 
			wchar_t				cheque_id[SEREDINA_GUIDLEN + 1];

		} seredina_lk_sale_data_t;

/*
ЛК  2011

Key - GUID бонуса.
Type Int Тип бонуса 1- Purchase (Начисление) 2- Return (списание) 
Sum Decimal Сумма бонусов Точность 2 
Remainder Decimal Остаток бонусов Точность 2 
Discount Decimal Скидка Точность 2 
ChargeDate datetime Дата начисления 
ActiveDate Datetime Дата начала действия 
DecrementDate Datetime Дата окончания действия (сгорания) 
Reason String Причина начисления/списания 
Comment String Комментарий к бонусу Max - 100 
BonusType Int Тип бонуса 1- Purchase (Начисление) 2- Return (списание) 
OperationType String Тип операции (аналог типа бонуса: B-начисление, D-списание) B- Purchase (Начисление) D- Return (списание)
Status String Статус 
CardNumber String Номер карты Max - 20 
ChequeNumber String Номер чека Max - 100 
PositionNumber String Номер позиции чека Max - 12 
CorrectionType int Тип коррекции бонуса 
CardId uniqueidentifier ID Карты 
ChequeId uniqueidentifier ID чека 
ChequeItemId uniqueidentifier ID позиции чека

ЛК 2015

Id - GUID бонуса.
ContactId guid Идентификатор контакта
CreatedDate datetime Дата создания
ActualStart datetime Дата активации
ActualEnd datetime Дата сгорания
OperationType integer Тип операции 1 - Purchase (покупка) 2 – Return (возврат)
Debet decimal Число начисленных бонусов При покупке - положительное, при возврате - отрицательное.
Credit decimal Число списанных бонусов При покупке - положительное, при возврате - отрицательное.
Remainder decimal Кол-во бонусных баллов, которое доступно на текущий момент (активные баллы)
CardId guid Идентификатор карты Бонус всегда связан с картой (даже в случае начислений по заданиям)
CardNumber string Номер карты Бонус всегда связан с картой (даже в случае начислений по заданиям)
ChequeId guid Идентификатор чека Выводится в случае, если бонус по чеку или по позиции чека
ChequeNumber string Номер чека Выводится в случае, если бонус по чеку или по позиции чека
PartnerId guid Идентификатор партнера Партнер балла
PartnerName string Название партнера Партнер балла
CampaignId guid Идентификатор кампании Бонус всегда связан с кампанией
CampaignName	string	Название кампании	Бонус всегда связан с кампанией	
RuleId	guid	Идентификатор	Выводится в случае, если бонус	42	правила начисления	связан с правилом	
RuleName	string	Название правила начисления	Выводится в случае, если бонус связан с правилом	
ChequeItemId	guid	Идентификатор позиции чека	Выводится в случае, если бонус по позиции чека	
ChequeItemProductName	string	Название товара позиции чека	Выводится в случае, если бонус по позиции чека	
ChequeItemParentId	guid	Идентификатор родительского чека позиции	Родительский чек позиции возвращается в случае, если позиция, по которой делается возврат, привязана к первичному чеку покупки (а не чеку возврата)	
ChequeItemParentNumber	string	Номер родительского чека позиции	Родительский чек позиции возвращается в случае, если позиция, по которой делается возврат, привязана к первичному чеку покупки (а не чеку возврата)
ParentName	string	Название «родителя» правила	Название (задания, ручного бонуса, импорт, смена уровня и т.п.) Выводится если ParentType = 1	
ParentType	integer	Тип «родителя» правила	0 - по чеку\позиции 1 - другое (задание, ручной бонус, импорт, смена уровня контакта, выпуск купонов, автосписание и т.п.)	

*/
///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_bonus_data_t
/// Содержит результат об одной бонусной операции
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_bonus_data 
		{  
			/// @debet - начисленные баллы. При покупке - положительное, при возврате - отрицательное
			double				debet;

			/// @credit - списанные баллы. При покупке - положительное, при возврате - отрицательное
			double				credit;

			/// @remainder decimal Кол-во бонусных баллов, которое доступно на текущий момент (активные баллы)
			double 				remainder;
			
			/// @discount Decimal Скидка Точность 2 
			double 				discount;
			
			/// @created_date datetime Дата создания
			seredina_datetime	created_date;          

			/// @start_date datetime Дата активации
			seredina_datetime	start_date;          

			/// @end_date 	datetime Дата сгорания
			seredina_datetime	end_date;          


			/// @bonus_id - GUID бонуса.
			wchar_t					  bonus_id[SEREDINA_GUIDLEN + 1];

			/// @contact_id - GUID контакта.
			wchar_t					  contact_id[SEREDINA_GUIDLEN + 1];

			/// @oper_type - Тип операции 1 - Purchase (покупка) 2 – Return (возврат)
			seredina_bonus_opertype_t oper_type;

			/// @status String Статус 
			wchar_t				status[SEREDINA_NMLEN + 1];
			/// @reason String Причина начисления/списания 
			wchar_t				reason[SEREDINA_NAMELEN + 1];
			/// @comment String Комментарий к бонусу Max - 100 
			wchar_t				comment[SEREDINA_COMMENTLEN + 1];


			/// @card_id - GUID карты.
			wchar_t				card_id[SEREDINA_GUIDLEN + 1];
			/// @card_number - номер карты.
			wchar_t				card_number[SEREDINA_CARDNUMLEN + 1];

			/// @cheque_id ID чека 
			wchar_t				cheque_id[SEREDINA_GUIDLEN + 1];
			/// @cheque_number String Номер чека Max - 100 
			wchar_t				cheque_number[SEREDINA_CHQNUMLEN + 1];

			/// @partner_id - GUID партнера продажи.
			wchar_t				partner_id[SEREDINA_GUIDLEN + 1];
			/// @partner_name - Имя партнера продажи.
			wchar_t				partner_name[SEREDINA_NAMELEN + 1];

			/// @campaign_id -  Идентификатор кампании Бонус всегда связан с кампанией
			wchar_t				campaign_id[SEREDINA_GUIDLEN + 1];
			/// @campaign_name	- Название кампании	Бонус всегда связан с кампанией	
			wchar_t				campaign_name[SEREDINA_NAMELEN + 1];

			///@cheque_item_id	guid	Идентификатор позиции чека	Выводится в случае, если бонус по позиции чека	
			wchar_t				cheque_item_id[SEREDINA_GUIDLEN + 1];
			///@cheque_item_product_name	string	Название товара позиции чека	Выводится в случае, если бонус по позиции чека	
			wchar_t				cheque_item_product_name[SEREDINA_NAMELEN + 1];

			///@position_number  Номер позиции чека  
			int					position_number;

			///@cheque_item_parent_id	guid	Идентификатор родительского чека позиции	Родительский чек позиции возвращается в случае, если позиция, по которой делается возврат, привязана к первичному чеку покупки (а не чеку возврата)	
			wchar_t				cheque_item_parent_id[SEREDINA_GUIDLEN + 1];
			///@cheque_item_parent_number	string	Номер родительского чека позиции	Родительский чек позиции возвращается в случае, если позиция, по которой делается возврат, привязана к первичному чеку покупки (а не чеку возврата)
			wchar_t				cheque_item_parent_number[SEREDINA_NAMELEN + 1];

		} seredina_lk_bonus_data_t;
		
///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_change_user_request_t
/// Содержит данные для выполнения операции изменения контактных данных
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_change_user_request 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_lk_change_user_request_t) 
			size_t				size_of_struct;
			
			/// @session_id - GUID сессии. 
			wchar_t				session_id[SEREDINA_GUIDLEN + 1];
			/// @contact_id - GUID контактных данных.
			wchar_t				contact_id[SEREDINA_GUIDLEN + 1];
			/// @card_number - номер карты.
			wchar_t				card_number[SEREDINA_CARDNUMLEN + 1];
			/// @last_name - фамилия.
			wchar_t				last_name[SEREDINA_NMLEN + 1];
			/// @first_name - имя.
			wchar_t				first_name[SEREDINA_NMLEN + 1];
			/// @middle_name - отчество.
			wchar_t				middle_name[SEREDINA_NMLEN + 1];
			/// @birthday - день рождения.
			seredina_date		birthday;
			/// @family_status - семейное положение.
			int 				family_status;
			/// @gender - пол.
			int 				gender;
			/// @email - электронная почта.
			wchar_t				email[SEREDINA_EMAILLEN + 1];
			/// @mobile_phone - номер мобильного.
			wchar_t				mobile_phone[SEREDINA_PHONELEN + 1];
			/// @home_phone - номер домашнего.
			wchar_t				home_phone[SEREDINA_PHONELEN + 1];
			/// @add_phone - номер дополнительного телефона.
			wchar_t				add_phone[SEREDINA_PHONELEN + 1];
			/// @postal_code - индекс почтовый.
			wchar_t				postal_code[SEREDINA_POSTALLEN + 1];
			/// @state_or_province - область.
			wchar_t				state_or_province[SEREDINA_ADDR1LEN + 1];
			/// @region_id - ид региона.
			wchar_t				region_id[SEREDINA_GUIDLEN + 1];
			/// @region - регион.
			wchar_t				region[SEREDINA_ADDR1LEN + 1];
			/// @city - город.
			wchar_t				сity[SEREDINA_ADDR1LEN + 1];
			/// @street - улица.
			wchar_t				street[SEREDINA_ADDR1LEN + 1];
			/// @home - дом.
			wchar_t				home[SEREDINA_HOMELEN + 1];
			/// @building - корпус.
			wchar_t				building[SEREDINA_HOMELEN + 1];
			/// @flat - квартира.
			wchar_t				flat[SEREDINA_HOMELEN + 1];
			/// @subscribe_by_email - тип подписки е-почта.
			int					subscribe_by_email;
			/// @subscribe_by_sms - тип подписки СМС.
			int					subscribe_by_sms;
			/// @code_word - кодовое слово (либо ПФР).
			wchar_t				code_word[SEREDINA_CARDNUMLEN + 1];
			/// @preferred_contact_method - тип контактирования.
			int					preferred_contact_method;
			/// @district - район города.
			wchar_t				district[SEREDINA_ADDR1LEN + 1];
			/// @locality_type - GUID тип локации адреса.
			wchar_t				locality_type[SEREDINA_GUIDLEN + 1];
			/// @street_type - GUID тип улицы.
			wchar_t				street_type[SEREDINA_GUIDLEN + 1];
			/// @transport_type - тип ТС.
			int					transport_type;
			/// @external_picklist - внешний список выбора транспорта.
			int					external_picklist;
			/// @registration_date - дата регистрации.
			seredina_date		registration_date;
			/// @registration_shop_id - GUID магазина регистрации.
			wchar_t				registration_shop_id[SEREDINA_GUIDLEN + 1];
			/// @registration_shop_code - код (название) магазина регистрации.
			wchar_t				registration_shop_code[SEREDINA_NMLEN + 1];
			/// @contact_owner - владелец контакта.
			wchar_t				contact_owner[SEREDINA_GUIDLEN + 1];
			/// @registration_сity - город регистрации  контакта.
			wchar_t				registration_сity[SEREDINA_ADDR1LEN + 1];
			/// @registration_person - персона  регистрации  контакта.
			wchar_t				registration_person[SEREDINA_NMLEN + 1];
			/// @source_value - регистратор.
			wchar_t				source_value[SEREDINA_NMLEN + 1];
			/// @card_source_value - номер карты регистратора или тип регистратора.
			int					card_source_value;
			/// @partner_category - категории партнеров.
			wchar_t				partner_category[SEREDINA_MAXPARTNERCATCNT][SEREDINA_PARTNERCATLEN + 1];
			/// @has_children - имеются ли дети.
			bool				has_children;
			/// @children_name1 - имя 1го ребенка.
			wchar_t				children_name1[SEREDINA_NMLEN + 1];
			/// @children_name2 - имя 2го ребенка.
			wchar_t				children_name2[SEREDINA_NMLEN + 1];
			/// @children_name1 - имя 3го ребенка.
			wchar_t				children_name3[SEREDINA_NMLEN + 1];
			/// @children_birthday1 - ДР 1го ребенка.
			seredina_date		children_birthday1;
			/// @children_birthday2 - ДР 2го ребенка.
			seredina_date		children_birthday2;
			/// @children_birthday3 - ДР 3го ребенка.
			seredina_date		children_birthday3;
			/// @children_gender1 - пол 1го ребенка.
			int					children_gender1;
			/// @children_gender2 - пол 2го ребенка.
			int					children_gender2;
			/// @children_gender3 - пол 3го ребенка.
			int					children_gender3;
			/// @login - логин контакта (почти всегда равен номеру карты).
			wchar_t				login[SEREDINA_CARDNUMLEN + 1];
			/// @password - пароль.
			wchar_t				password[SEREDINA_PASSWORDLEN + 1];
			/// @add_info - дополнительные примечания.
			wchar_t				add_info[SEREDINA_ADDINFOLEN + 1];
			/// @subscribe_by_phone - тип подписки телефон.
			int					subscribe_by_phone;
			/// @use_sms_validation - использовать СМС-подтверждения.
			seredina_bool_t		use_sms_validation;
			/// @partner_id - GUID организации-партнера.
			wchar_t				partner_id[SEREDINA_GUIDLEN + 1];
            /// @mobile_verified - если 0 - не определено, 1 - false, 2 - true
            seredina_tribool_t  mobile_verified;
            /// @email_verified - если 0 - не определено, 1 - false, 2 - true
            seredina_tribool_t  email_verified;
			/// @org_partner - CRM-организация партнера.
            wchar_t				org_partner[SEREDINA_NAMELEN + 1];
            /// @ext_attrs - массив расширенных атрибутов контакта
            seredina_extattr_t  ext_attrs[SEREDINA_MAXEXTATTRCOUNT];
		} seredina_lk_change_user_request_t;

///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_search_response_t
/// Содержит данные после поиска  контактных данных
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_search_response 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_lk_search_response_t) 
			size_t				size_of_struct;
			
			/// @contact_id - GUID контактных данных.
			wchar_t				contact_id[SEREDINA_GUIDLEN + 1];
			/// @card_number - номер карты для поиска
			wchar_t				card_number[SEREDINA_CARDNUMLEN + 1];
			/// @last_name - фамилия.
			wchar_t				last_name[SEREDINA_NMLEN + 1];
			/// @first_name - имя.
			wchar_t				first_name[SEREDINA_NMLEN + 1];
			/// @middle_name - отчество.
			wchar_t				middle_name[SEREDINA_NMLEN + 1];
			/// @birthday - день рождения.
			seredina_date		birthday;
			/// @email - электронная почта.
			wchar_t				email[SEREDINA_EMAILLEN + 1];
			/// @mobile_phone - номер мобильного.
			wchar_t				mobile_phone[SEREDINA_PHONELEN + 1];
			/// @login - логин контакта (НЕ всегда равен номеру карты).
			wchar_t				login[SEREDINA_CARDNUMLEN + 1];
            /// @status - код статуса карты
            seredina_cardstatus_type_t  status;
            /// @status - код статуса карты
            wchar_t             status_text[SEREDINA_NMLEN + 1];
            /// @full_balance - полный баланс карты
            double              full_balance;
            /// @balance - активный баланс карты
            double              balance;
		} seredina_lk_search_response_t; 
		
///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_search_rec_t
/// Содержит данные для выполнения операции поиска контактных данных
///-----------------------------------------------------------------------------
typedef struct tag_seredina_lk_search_rec 
		{  
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(seredina_lk_search_rec_t) 
			size_t				size_of_struct;
			
			/// @max_rec_num - максимальное количество записей в выдаче.
			int					max_rec_num;
			/// @card_number - номер карты для поиска
			wchar_t				card_number[SEREDINA_CARDNUMLEN + 1];
			/// @last_name - фамилия.
			wchar_t				last_name[SEREDINA_NMLEN + 1];
			/// @first_name - имя.
			wchar_t				first_name[SEREDINA_NMLEN + 1];
			/// @middle_name - отчество.
			wchar_t				middle_name[SEREDINA_NMLEN + 1];
			/// @birthday - день рождения.
			seredina_date		birthday;
			/// @email - электронная почта.
			wchar_t				email[SEREDINA_EMAILLEN + 1];
			/// @mobile_phone - номер мобильного.
			wchar_t				mobile_phone[SEREDINA_PHONELEN + 1];

			/// @min_date - минимальная дата интервала (день рождения или дата по смыслу, например дата чека).
			seredina_date		min_date;
			/// @max_date - максимальная дата интервала (день рождения или дата по смыслу, например дата чека).
			seredina_date		max_date;

            /// @find_all_cards - если true - всегда искать все карты контакта, если есть возможность
			seredina_bool_t     find_all_cards;

		} seredina_lk_search_rec_t; 

///-----------------------------------------------------------------------------
/// Структура  @seredina_lk_contact_request_t
/// Содержит контактные данные 
///-----------------------------------------------------------------------------
typedef tag_seredina_lk_change_user_request seredina_lk_user_contact_data_t;

///-----------------------------------------------------------------------------
/// Тип seredina_t - дескриптор объекта библиотеки процессинга
///-----------------------------------------------------------------------------
struct tag_seredina_handle { const char ch_signature; };

typedef tag_seredina_handle* seredina_t;


///-----------------------------------------------------------------------------
/// Обработка товарных предложений ДоПродажника
///-----------------------------------------------------------------------------

    typedef seredina_extattr_t   proloy_extattr_t; 
    typedef seredina_t           proloy_handle_t;
    typedef seredina_result_t    proloy_result_t;
    typedef seredina_request_t   proloy_procrequest_t; 
    typedef seredina_response_t  proloy_procresponse_t;


    /// @proloy_offer_request_t - структура для запроса оферов, содержит в основном данные сегментирования.
    typedef struct tag_proloy_offer_request
    {
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(proloy_offer_request_t) 
			size_t				size_of_struct;

            /// @contact_id - ID контактных данных.
			wchar_t				    contact_id[SEREDINA_GUIDLEN + 1];
			/// @card_number - номер карты для поиска
			wchar_t				    card_number[SEREDINA_CARDNUMLEN + 1];
            /// @email - электронная почта.
			wchar_t				    email[SEREDINA_EMAILLEN + 1];
			/// @mobile_phone - номер мобильного.
			wchar_t				    mobile_phone[SEREDINA_PHONELEN + 1];
			/// @gender - пол.
            proloy_gender_t         gender;
            /// @birthday - день рождения.
			seredina_date		    birthday;
            /// @age - возраст.
			int                     age;
			/// @family_status - семейное положение.
			proloy_family_status_t  family_status;
			/// @has_children - имеются ли дети.
            seredina_bool_t         has_children;
            /// возможные расширенные параметры
            proloy_extattr_t        ext_params[PROLOY_MAX_EXT_PARAMS];
    } proloy_offer_request_t;

    typedef struct tag_proloy_offer_item
    {
    	    /// @size_of_struct - размер структуры, должен быть установлен перед вызовом
	        /// в значение sizeof(proloy_offer_item_t) 
	        size_t				size_of_struct;
            /// @id - ИД офера, данные ДЕНОРМАЛИЗОВАННЫЕ 
            wchar_t             offer_id[SEREDINA_GUIDLEN + 1];
            /// @name - название офера, данные ДЕНОРМАЛИЗОВАННЫЕ 
            wchar_t             offer_name[SEREDINA_COMMENTLEN + 1];
            /// @id - ИД элемента офера
            wchar_t             offer_item_id[SEREDINA_GUIDLEN + 1];
            /// @name - название элемента офера
            wchar_t             offer_item_name[SEREDINA_COMMENTLEN + 1];
            /// @description - описание
            wchar_t             description[SEREDINA_MAXSTRLEN + 1];
            /// @message - сообщение для кассира
            wchar_t             message[SEREDINA_MSGLEN + 1];
            /// @article - код товара
            wchar_t		 		article[SEREDINA_ARTLEN + 1];
			/// @article_name - наименование товара
            wchar_t		 		article_name[SEREDINA_ARTNMLEN + 1];
			/// @category - категория товара
            wchar_t		 		category[SEREDINA_ARTNMLEN+ 1];
			/// @subcategory - подкатегория товара
            wchar_t		 		subcategory[SEREDINA_ARTNMLEN + 1];
			/// @category - категория товара
            wchar_t		 		manufacturer[SEREDINA_COMMENTLEN + 1];
			/// @price - цена 
			double				price;
			/// @quantity - количество
			double              quantity;
			/// @min_quantity - минимальное количество для акции
			double              min_quantity;
            /// @beg_date - начало действия акции
            seredina_date       beg_date;
            /// @end_date - окончание действия акции
            seredina_date       end_date;
            /// @article_url - URL страницы описания
            wchar_t             article_url[SEREDINA_ARTNMLEN*2 + 1];
            /// @need_print - флаг печати на слипе
            bool                need_print: 1;
    } proloy_offer_item_t; 

    /// @proloy_offer_response_t - структура для результата офера. 
    /// сейчас содержит только 1 первый элемент массива оферов
    typedef struct tag_proloy_offer_response
    {
	        /// @size_of_struct - размер структуры, должен быть установлен перед вызовом
	        /// в значение sizeof(proloy_offer_response_t) 
	        size_t				size_of_struct;

            /// @main_offer - PROLOY_MAX_MAIN_OFFERS самых важных оферов, остальные читать через функции получения элементов оферов
            proloy_offer_item_t main_offers[PROLOY_MAX_MAIN_OFFERS];

            /// @request_id - ID транзакции запроса офера.
			wchar_t             request_id[SEREDINA_NAMELEN + 1];
    } proloy_offer_response_t;

    /// @proloy_offer_feedback_t - структура для запроса установки данных об обратной связи от кассира на предложение покупателю.
    typedef struct tag_proloy_offer_feedback
    {
			/// @size_of_struct - размер структуры, должен быть установлен перед вызовом
			/// в значение sizeof(proloy_offer_feedback_t) 
			size_t				          size_of_struct;

            /// @request_id - ID транзакции запроса офера.
			wchar_t                       request_id[SEREDINA_NAMELEN + 1];

            /// @feedback - код обратной связи.
            proloy_offer_feedback_code_t  feedback;
    } proloy_offer_feedback_t;



#pragma pack(pop)


#ifdef __cplusplus
}  //extern "C" {
#endif


#endif // __PLPOSPROCDEFS_H__
