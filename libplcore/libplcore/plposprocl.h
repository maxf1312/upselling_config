#pragma once 

#ifndef __PLPOSPROCL_H__
#define __PLPOSPROCL_H__

#include <cstddef>
#include "plposprocdefs.h"


///-----------------------------------------------------------------------------
///
/// Программный интерфейс для работы с процессингом 
///
///-----------------------------------------------------------------------------
#ifdef _WINDOWS
#  if defined(ZSPOSPROCL_EXPORTS) || defined(ZSUTILS_EXPORTS)
#    define ZSPOSPROCL_API __declspec(dllexport)
#  else
#		ifdef ZSPOSPROCL_DLIMPORT
#			define ZSPOSPROCL_API 
#		else
#			define ZSPOSPROCL_API __declspec(dllimport)
#		endif
#  endif
#else 
#  define ZSPOSPROCL_API 
#endif // _WINDOWS

#ifdef __cplusplus
extern "C" {
#endif


ZSPOSPROCL_API int seredina_open(seredina_t* h, const wchar_t* processing_id);
ZSPOSPROCL_API int seredina_close(seredina_t h);
ZSPOSPROCL_API int seredina_get_last_result(
				seredina_t h, 
				seredina_result_t* p_res
	);

ZSPOSPROCL_API int seredina_check_connection(seredina_t h);

ZSPOSPROCL_API int seredina_get_balance(
				seredina_t h, 
				const wchar_t* card_number, 
				seredina_result_t* p_res, 
				seredina_balance_result_t* p_balance
	);

ZSPOSPROCL_API int seredina_cheque_bonus_count(
				seredina_t		h, 
				const wchar_t*	card_number, 
				const wchar_t*	cheque_number, 
				double			summ,
				double			discount,
				double			bonus_to_count,
				seredina_result_t*			p_res, 
				seredina_cheque_result_t*	p_cheque_res
	);

ZSPOSPROCL_API int seredina_cheque_bonus_discount(
				seredina_t		h, 
				const wchar_t*	card_number, 
				const wchar_t*	cheque_number, 
				double			summ,
				double			discount,
				double			paid_by_bonus,
				seredina_result_t*			p_res, 
				seredina_cheque_result_t*	p_cheque_res
	);

ZSPOSPROCL_API int seredina_cheque_with_discount(
				seredina_t		h, 
				const wchar_t*	card_number, 
				const wchar_t*	cheque_number, 
				double			summ,
				double			discount,
				seredina_result_t*			p_res, 
				seredina_cheque_result_t*	p_cheque_res
	);

ZSPOSPROCL_API int seredina_cheque_return(
				seredina_t		h, 
				const wchar_t*	card_number, 
				const wchar_t*	cheque_number, 
				const wchar_t*	rrn, 
				double			summ,
				double			discount,
				double			paid_by_bonus,
				seredina_result_t*			p_res, 
				seredina_cheque_result_t*	p_cheque_res
	);

ZSPOSPROCL_API int seredina_cheque_rollback(
				seredina_t			h, 
				const wchar_t*		card_number, 
				const wchar_t*		rrn, 
				seredina_tran_id_t	id_transaction,
				seredina_result_t*			p_res 
	);


ZSPOSPROCL_API int seredina_cheque_set_type(
				seredina_t				h, 
				seredina_cheque_type_t	chq_type
	);

ZSPOSPROCL_API int seredina_cheque_get_type(
				seredina_t				h, 
				seredina_cheque_type_t*	chq_type
	);

///-----------------------------------------------------------------------------
/// @seredina_exec_req - выполнение универсального запроса, 
///                      выполняется драйвером процессинга
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int seredina_exec_req(
				seredina_t					h,
				seredina_request_t const	*req,
				seredina_response_t			*resp
	);

///-----------------------------------------------------------------------------
/// Обработка элементов чека 
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int seredina_req_chqitem_count(
				seredina_t		h
	);

ZSPOSPROCL_API int seredina_req_chqitem_clear(
				seredina_t		h
	);

ZSPOSPROCL_API int seredina_req_chqitem_get(
				seredina_t		h, 
				int			index, 
				seredina_cheque_item_t*	p_item
	);

ZSPOSPROCL_API int seredina_req_chqitem_set(
				seredina_t		h, 
				int			index, 
				seredina_cheque_item_t*	p_item
	);

ZSPOSPROCL_API int seredina_res_chqitem_count(
				seredina_t		h
	);

ZSPOSPROCL_API int seredina_res_chqitem_get(
				seredina_t		h, 
				int			index, 
				seredina_cheque_item_t*	p_item
	);

///-----------------------------------------------------------------------------
/// Обработка расширенных атрибутов чека 
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int seredina_req_chqextattr_count(
				seredina_t		h
	);

ZSPOSPROCL_API int seredina_req_chqextattr_clear(
				seredina_t		h
	);

ZSPOSPROCL_API int seredina_req_chqextattr_get(
				seredina_t		h, 
				int			index, 
				seredina_extattr_t*	p_item
	);

ZSPOSPROCL_API int seredina_req_chqextattr_set(
				seredina_t		h, 
				int			index, 
				seredina_extattr_t*	p_item
	);

ZSPOSPROCL_API int seredina_res_chqextattr_count(
				seredina_t		h
	);

ZSPOSPROCL_API int seredina_res_chqextattr_get(
				seredina_t		h, 
				int				index, 
				seredina_extattr_t*	p_item
	);

///-----------------------------------------------------------------------------
/// Обработка расширенных атрибутов элементов чека 
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int seredina_req_chqitemextattr_count(
				seredina_t		h,
				int				item_index 
	);

ZSPOSPROCL_API int seredina_req_chqitemextattr_clear(
				seredina_t		h,
				int				item_index
	);

ZSPOSPROCL_API int seredina_req_chqitemextattr_get(
				seredina_t		h, 
				int				item_index, 
				int				attr_index, 
				seredina_extattr_t*	p_item
	);

ZSPOSPROCL_API int seredina_req_chqitemextattr_set(
				seredina_t		h, 
				int				item_index, 
				int				attr_index, 
				seredina_extattr_t*	p_item
	);

ZSPOSPROCL_API int seredina_res_chqitemextattr_count(
				seredina_t		h, 
				int				item_index				
	);

ZSPOSPROCL_API int seredina_res_chqitemextattr_get(
				seredina_t		h, 
				int				item_index, 
				int				attr_index, 
				seredina_extattr_t*	p_item
	);

///-----------------------------------------------------------------------------
/// Обработка операций личного кабинета - уровень процессинга 
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int seredina_lk_authorize(
				seredina_t			h,
				const wchar_t		*login,
				const wchar_t		*password, 
				seredina_lk_auth_result_t*	res
	);
	
ZSPOSPROCL_API int seredina_lk_get_session(
				seredina_t					h,
				seredina_lk_auth_result_t*	res
	);
	
ZSPOSPROCL_API int seredina_lk_change_user_data(
				seredina_t			h,
				seredina_lk_change_user_request_t const	*req,
				seredina_lk_change_user_result_t		*res
	);

ZSPOSPROCL_API int seredina_lk_get_user_data(
				seredina_t		h,
				wchar_t	const					*contact_id,
				seredina_result_t				*response,
				seredina_lk_user_contact_data_t	*contact_data
	);

ZSPOSPROCL_API int seredina_lk_change_user_password(
				seredina_t			h,
				wchar_t const		*contact_id,
				wchar_t const		*old_psw,
				wchar_t const		*new_psw,
				seredina_result_t	*response
	);

ZSPOSPROCL_API int seredina_lk_find_contacts(
				seredina_t				 		h,
				seredina_lk_search_rec_t const	*find_data,
				seredina_result_t				*response, 
				size_t							*count_of_found
	);

ZSPOSPROCL_API int seredina_lk_find_contacts_get(
				seredina_t							h,
				size_t const						idx_from,
				size_t const						count_to_get,
				seredina_lk_search_response_t		*user_data_buffer				
	);

ZSPOSPROCL_API int seredina_lk_find_contacts_clear(
				seredina_t							h				
	);
	
ZSPOSPROCL_API int seredina_lk_main_data_load(
				seredina_t		 	h,
				wchar_t const		*main_data_id,
				seredina_result_t	*response, 
				size_t*				len_of_result
	);

ZSPOSPROCL_API int seredina_lk_main_data_get(
				seredina_t		 	h,
				wchar_t const		*main_data_id,
				wchar_t 			*str_buf,
				size_t				start_of_chunk,
				size_t				size_of_chunk
	);

ZSPOSPROCL_API int seredina_lk_main_data_clear(
				seredina_t		 	h, 
				wchar_t const		*main_data_id
	);

ZSPOSPROCL_API int seredina_lk_validate_card(
				seredina_t				 			h,
				seredina_lk_search_rec_t const		*find_data,
				seredina_lk_validate_card_result_t	*response
	);

ZSPOSPROCL_API int seredina_lk_sales_data_load(
				seredina_t				 		h,
				seredina_lk_search_rec_t const	*find_data,
				seredina_result_t				*response, 
				size_t							*count_of_found
	);
	
ZSPOSPROCL_API int seredina_lk_sales_data_get(
				seredina_t				h,
				size_t const			idx_from, 
				size_t const			count_to_get,
				seredina_lk_sale_data_t *buffer
	);

ZSPOSPROCL_API int seredina_lk_sales_data_clear(
				seredina_t				h
	);

ZSPOSPROCL_API int seredina_lk_get_user_data(
				seredina_t		h,
				wchar_t	const					*contact_id,
				seredina_result_t				*response,
				seredina_lk_user_contact_data_t	*contact_data
	);

ZSPOSPROCL_API int seredina_lk_lock_card(
				seredina_t				 		h,
				wchar_t	const*					cardnumber,
				const bool						lock_unlock,
				seredina_result_t				*response
	);


ZSPOSPROCL_API int seredina_lk_bonus_data_load(
				seredina_t				 		h,
				seredina_lk_search_rec_t const	*find_data,
				seredina_result_t				*response, 
				size_t							*count_of_found
	);
	
ZSPOSPROCL_API int seredina_lk_bonus_data_get(
				seredina_t				 h,
				size_t const			 idx_from, 
				size_t const			 count_to_get,
				seredina_lk_bonus_data_t *buffer
	);

ZSPOSPROCL_API int seredina_lk_bonus_data_clear(
				seredina_t				h
	);

ZSPOSPROCL_API int seredina_lk_verify_sms_code(
				seredina_t							h,
				wchar_t	const*						phonenumber,
				wchar_t	const*						sms_code,
				seredina_lk_change_user_result_t*	res
	);

ZSPOSPROCL_API int seredina_lk_bind_card(
				seredina_t				 		h,
				const wchar_t*                  cardnumber,
                const wchar_t*                  contact_id,
				const bool						bind_unbind,
				seredina_lk_change_user_result_t *response
	);

ZSPOSPROCL_API int seredina_lk_change_card(
				seredina_t				 		 h,
				const wchar_t*                   cardnumber_to,
                const wchar_t*                   cardnumber_from,
				seredina_lk_change_user_result_t *response
	);

ZSPOSPROCL_API int seredina_lk_lock_contact(
				seredina_t				 		h,
				wchar_t	const*					contact_id,
				const bool						lock_unlock,
				seredina_result_t				*response
	);

ZSPOSPROCL_API int proloy_get_resp_field_text_len(
                seredina_t          h,
                proloy_field_code_t field_code
    );

ZSPOSPROCL_API int proloy_get_resp_field_text(
                seredina_t          h,
                proloy_field_code_t field_code,
                wchar_t*            buffer,
                int                 buf_len
    );


///-----------------------------------------------------------------------------
/// @proloy_exec_offer_req - выполнение запроса офера, 
///                          выполняется драйвером процессинга офера
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int proloy_exec_offer_req(
				proloy_handle_t     		    h,
				proloy_procrequest_t const	    *req,
                proloy_offer_request_t const    *offer_req,
				proloy_procresponse_t		    *resp,
				proloy_offer_response_t			*offer_resp
	);

///-----------------------------------------------------------------------------
/// @proloy_exec_offer_feedback - выполнение запроса на отметку обратной связи, 
///                               выполняется драйвером процессинга офера
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int proloy_exec_offer_feedback(
				proloy_handle_t                 h,
				proloy_offer_feedback_t const   *feedback_req,
                proloy_result_t                 *resp
	);

///-----------------------------------------------------------------------------
/// Обработка списка оферов 
///
/// @proloy_res_offer_item_count - количество элементов типа офер в ответе
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int proloy_res_offer_item_count(
				proloy_handle_t		h
	);

///-----------------------------------------------------------------------------
/// @proloy_res_offer_item_get - количество элементов типа офер в ответе
///-----------------------------------------------------------------------------
ZSPOSPROCL_API int proloy_res_offer_item_get(
				proloy_handle_t		    h, 
				int			            index, 
				proloy_offer_item_t*	p_item
	);



#ifdef __cplusplus
}  //extern "C" {
#endif


#endif // __PLPOSPROCL_H__
