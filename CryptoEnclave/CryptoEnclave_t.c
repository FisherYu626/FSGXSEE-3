#include "CryptoEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


typedef struct ms_ecall_init_t {
	unsigned char* ms_keyF1;
	unsigned char* ms_keyF2;
	unsigned char* ms_keyF3;
	size_t ms_len;
} ms_ecall_init_t;

typedef struct ms_ecall_addDoc_t {
	char* ms_doc_id;
	size_t ms_id_length;
	char* ms_content;
	int ms_content_length;
} ms_ecall_addDoc_t;

typedef struct ms_ecall_delDoc_t {
	char* ms_doc_id;
	size_t ms_id_length;
} ms_ecall_delDoc_t;

typedef struct ms_ecall_search_t {
	const char* ms_keyword;
	size_t ms_len;
} ms_ecall_search_t;

typedef struct ms_ecall_InsertVct_t {
	int ms_vword;
	int ms_c;
	int ms_t;
} ms_ecall_InsertVct_t;

typedef struct ms_ecall_searchToken_t {
	unsigned char* ms_token;
	int ms_token_len;
} ms_ecall_searchToken_t;

typedef struct ms_ecall_search_tkq_t {
	unsigned char* ms_token;
	int ms_token_len;
} ms_ecall_search_tkq_t;

typedef struct ms_ecall_verifyIDEnc_t {
	unsigned char* ms_ID;
	size_t ms_len;
} ms_ecall_verifyIDEnc_t;

typedef struct ms_ecall_SendOpIdN_t {
	int ms_op;
	unsigned char* ms_IdN;
	int ms_len;
} ms_ecall_SendOpIdN_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_transfer_encrypted_entries_t {
	const void* ms_t1_u_arr;
	const void* ms_t1_v_arr;
	const void* ms_t2_u_arr;
	const void* ms_t2_v_arr;
	int ms_pair_count;
	int ms_rand_size;
} ms_ocall_transfer_encrypted_entries_t;

typedef struct ms_ocall_retrieve_encrypted_doc_t {
	const char* ms_del_id;
	size_t ms_del_id_len;
	unsigned char* ms_encrypted_content;
	size_t ms_maxLen;
	int* ms_length_content;
	size_t ms_int_len;
} ms_ocall_retrieve_encrypted_doc_t;

typedef struct ms_ocall_del_encrypted_doc_t {
	const char* ms_del_id;
	size_t ms_del_id_len;
} ms_ocall_del_encrypted_doc_t;

typedef struct ms_ocall_retrieve_M_c_t {
	unsigned char* ms__u_prime;
	size_t ms__u_prime_size;
	unsigned char* ms__v_prime;
	size_t ms_maxLen;
	int* ms__v_prime_size;
	size_t ms_int_len;
} ms_ocall_retrieve_M_c_t;

typedef struct ms_ocall_del_M_c_value_t {
	const unsigned char* ms__u_prime;
	size_t ms__u_prime_size;
} ms_ocall_del_M_c_value_t;

typedef struct ms_ocall_query_tokens_entries_t {
	const void* ms_Q_w_u_arr;
	const void* ms_Q_w_id_arr;
	int ms_pair_count;
	int ms_rand_size;
} ms_ocall_query_tokens_entries_t;

typedef struct ms_ocall_retrieve_VGama_t {
	unsigned char* ms_L_text;
	int ms_L_length;
	unsigned char* ms_V_text;
	int ms_V_length;
	unsigned char* ms_Gama_text;
	int ms_Gama_length;
} ms_ocall_retrieve_VGama_t;

typedef struct ms_ocall_receive_VxGamaX_t {
	unsigned char* ms_vx_text;
	int ms_vx_length;
	unsigned char* ms_gamax_plain;
	int ms_gamax_plain_len;
	int ms_vi;
} ms_ocall_receive_VxGamaX_t;

typedef struct ms_ocall_receive_R_t {
	unsigned char* ms_R;
	int ms_R_len;
} ms_ocall_receive_R_t;

typedef struct ms_ocall_sendLVGAMA_t {
	unsigned char* ms_L2;
	int ms_L2_len;
	unsigned char* ms_V2;
	int ms_V2_len;
	unsigned char* ms_gama_X2_plain;
	int ms_gama_X2_len;
} ms_ocall_sendLVGAMA_t;

typedef struct ms_ocall_retrieve_PKi_t {
	unsigned char* ms_Addr;
	int ms_addr_len;
	unsigned char* ms_PKi;
	int ms_PK_len;
} ms_ocall_retrieve_PKi_t;

typedef struct ms_ocall_transfer_uv_pairs_t {
	const void* ms_u_arr;
	const void* ms_v_arr;
	int ms_pair_count;
	int ms_rand_size;
} ms_ocall_transfer_uv_pairs_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL sgx_ecall_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_t* ms = SGX_CAST(ms_ecall_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_keyF1 = ms->ms_keyF1;
	size_t _tmp_len = ms->ms_len;
	size_t _len_keyF1 = _tmp_len;
	unsigned char* _in_keyF1 = NULL;
	unsigned char* _tmp_keyF2 = ms->ms_keyF2;
	size_t _len_keyF2 = _tmp_len;
	unsigned char* _in_keyF2 = NULL;
	unsigned char* _tmp_keyF3 = ms->ms_keyF3;
	size_t _len_keyF3 = _tmp_len;
	unsigned char* _in_keyF3 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keyF1, _len_keyF1);
	CHECK_UNIQUE_POINTER(_tmp_keyF2, _len_keyF2);
	CHECK_UNIQUE_POINTER(_tmp_keyF3, _len_keyF3);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keyF1 != NULL && _len_keyF1 != 0) {
		if ( _len_keyF1 % sizeof(*_tmp_keyF1) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyF1 = (unsigned char*)malloc(_len_keyF1);
		if (_in_keyF1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyF1, _len_keyF1, _tmp_keyF1, _len_keyF1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_keyF2 != NULL && _len_keyF2 != 0) {
		if ( _len_keyF2 % sizeof(*_tmp_keyF2) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyF2 = (unsigned char*)malloc(_len_keyF2);
		if (_in_keyF2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyF2, _len_keyF2, _tmp_keyF2, _len_keyF2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_keyF3 != NULL && _len_keyF3 != 0) {
		if ( _len_keyF3 % sizeof(*_tmp_keyF3) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyF3 = (unsigned char*)malloc(_len_keyF3);
		if (_in_keyF3 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyF3, _len_keyF3, _tmp_keyF3, _len_keyF3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_init(_in_keyF1, _in_keyF2, _in_keyF3, _tmp_len);

err:
	if (_in_keyF1) free(_in_keyF1);
	if (_in_keyF2) free(_in_keyF2);
	if (_in_keyF3) free(_in_keyF3);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_addDoc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_addDoc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_addDoc_t* ms = SGX_CAST(ms_ecall_addDoc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_doc_id = ms->ms_doc_id;
	size_t _tmp_id_length = ms->ms_id_length;
	size_t _len_doc_id = _tmp_id_length;
	char* _in_doc_id = NULL;
	char* _tmp_content = ms->ms_content;
	int _tmp_content_length = ms->ms_content_length;
	size_t _len_content = _tmp_content_length;
	char* _in_content = NULL;

	CHECK_UNIQUE_POINTER(_tmp_doc_id, _len_doc_id);
	CHECK_UNIQUE_POINTER(_tmp_content, _len_content);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_doc_id != NULL && _len_doc_id != 0) {
		if ( _len_doc_id % sizeof(*_tmp_doc_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_doc_id = (char*)malloc(_len_doc_id);
		if (_in_doc_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_doc_id, _len_doc_id, _tmp_doc_id, _len_doc_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_content != NULL && _len_content != 0) {
		if ( _len_content % sizeof(*_tmp_content) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_content = (char*)malloc(_len_content);
		if (_in_content == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_content, _len_content, _tmp_content, _len_content)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_addDoc(_in_doc_id, _tmp_id_length, _in_content, _tmp_content_length);

err:
	if (_in_doc_id) free(_in_doc_id);
	if (_in_content) free(_in_content);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_delDoc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_delDoc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_delDoc_t* ms = SGX_CAST(ms_ecall_delDoc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_doc_id = ms->ms_doc_id;
	size_t _tmp_id_length = ms->ms_id_length;
	size_t _len_doc_id = _tmp_id_length;
	char* _in_doc_id = NULL;

	CHECK_UNIQUE_POINTER(_tmp_doc_id, _len_doc_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_doc_id != NULL && _len_doc_id != 0) {
		if ( _len_doc_id % sizeof(*_tmp_doc_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_doc_id = (char*)malloc(_len_doc_id);
		if (_in_doc_id == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_doc_id, _len_doc_id, _tmp_doc_id, _len_doc_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_delDoc(_in_doc_id, _tmp_id_length);

err:
	if (_in_doc_id) free(_in_doc_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_search(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_search_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_search_t* ms = SGX_CAST(ms_ecall_search_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_keyword = ms->ms_keyword;
	size_t _tmp_len = ms->ms_len;
	size_t _len_keyword = _tmp_len;
	char* _in_keyword = NULL;

	CHECK_UNIQUE_POINTER(_tmp_keyword, _len_keyword);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_keyword != NULL && _len_keyword != 0) {
		if ( _len_keyword % sizeof(*_tmp_keyword) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_keyword = (char*)malloc(_len_keyword);
		if (_in_keyword == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_keyword, _len_keyword, _tmp_keyword, _len_keyword)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_search((const char*)_in_keyword, _tmp_len);

err:
	if (_in_keyword) free(_in_keyword);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_printHelloWorld(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_printHelloWorld();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_InsertVct(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_InsertVct_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_InsertVct_t* ms = SGX_CAST(ms_ecall_InsertVct_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_InsertVct(ms->ms_vword, ms->ms_c, ms->ms_t);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_searchToken(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_searchToken_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_searchToken_t* ms = SGX_CAST(ms_ecall_searchToken_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_token = ms->ms_token;
	int _tmp_token_len = ms->ms_token_len;
	size_t _len_token = _tmp_token_len;
	unsigned char* _in_token = NULL;

	CHECK_UNIQUE_POINTER(_tmp_token, _len_token);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_token != NULL && _len_token != 0) {
		if ( _len_token % sizeof(*_tmp_token) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_token = (unsigned char*)malloc(_len_token);
		if (_in_token == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_token, _len_token, _tmp_token, _len_token)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_searchToken(_in_token, _tmp_token_len);

err:
	if (_in_token) free(_in_token);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_search_tkq(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_search_tkq_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_search_tkq_t* ms = SGX_CAST(ms_ecall_search_tkq_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_token = ms->ms_token;
	int _tmp_token_len = ms->ms_token_len;
	size_t _len_token = _tmp_token_len;
	unsigned char* _in_token = NULL;

	CHECK_UNIQUE_POINTER(_tmp_token, _len_token);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_token != NULL && _len_token != 0) {
		if ( _len_token % sizeof(*_tmp_token) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_token = (unsigned char*)malloc(_len_token);
		if (_in_token == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_token, _len_token, _tmp_token, _len_token)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_search_tkq(_in_token, _tmp_token_len);

err:
	if (_in_token) free(_in_token);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_verifyIDEnc(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_verifyIDEnc_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_verifyIDEnc_t* ms = SGX_CAST(ms_ecall_verifyIDEnc_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_ID = ms->ms_ID;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ID = _tmp_len;
	unsigned char* _in_ID = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ID, _len_ID);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ID != NULL && _len_ID != 0) {
		if ( _len_ID % sizeof(*_tmp_ID) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ID = (unsigned char*)malloc(_len_ID);
		if (_in_ID == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ID, _len_ID, _tmp_ID, _len_ID)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_verifyIDEnc(_in_ID, _tmp_len);

err:
	if (_in_ID) free(_in_ID);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_SendOpIdN(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_SendOpIdN_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_SendOpIdN_t* ms = SGX_CAST(ms_ecall_SendOpIdN_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_IdN = ms->ms_IdN;
	int _tmp_len = ms->ms_len;
	size_t _len_IdN = _tmp_len;
	unsigned char* _in_IdN = NULL;

	CHECK_UNIQUE_POINTER(_tmp_IdN, _len_IdN);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_IdN != NULL && _len_IdN != 0) {
		if ( _len_IdN % sizeof(*_tmp_IdN) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_IdN = (unsigned char*)malloc(_len_IdN);
		if (_in_IdN == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_IdN, _len_IdN, _tmp_IdN, _len_IdN)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_SendOpIdN(ms->ms_op, _in_IdN, _tmp_len);

err:
	if (_in_IdN) free(_in_IdN);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[10];
} g_ecall_table = {
	10,
	{
		{(void*)(uintptr_t)sgx_ecall_init, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_addDoc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_delDoc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_search, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_printHelloWorld, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_InsertVct, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_searchToken, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_search_tkq, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_verifyIDEnc, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_SendOpIdN, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[18][10];
} g_dyn_entry_table = {
	18,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_transfer_encrypted_entries(const void* t1_u_arr, const void* t1_v_arr, const void* t2_u_arr, const void* t2_v_arr, int pair_count, int rand_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_t1_u_arr = pair_count * rand_size;
	size_t _len_t1_v_arr = pair_count * rand_size;
	size_t _len_t2_u_arr = pair_count * rand_size;
	size_t _len_t2_v_arr = pair_count * rand_size;

	ms_ocall_transfer_encrypted_entries_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_transfer_encrypted_entries_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(t1_u_arr, _len_t1_u_arr);
	CHECK_ENCLAVE_POINTER(t1_v_arr, _len_t1_v_arr);
	CHECK_ENCLAVE_POINTER(t2_u_arr, _len_t2_u_arr);
	CHECK_ENCLAVE_POINTER(t2_v_arr, _len_t2_v_arr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t1_u_arr != NULL) ? _len_t1_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t1_v_arr != NULL) ? _len_t1_v_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t2_u_arr != NULL) ? _len_t2_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (t2_v_arr != NULL) ? _len_t2_v_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_transfer_encrypted_entries_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_transfer_encrypted_entries_t));
	ocalloc_size -= sizeof(ms_ocall_transfer_encrypted_entries_t);

	if (t1_u_arr != NULL) {
		ms->ms_t1_u_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t1_u_arr, _len_t1_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t1_u_arr);
		ocalloc_size -= _len_t1_u_arr;
	} else {
		ms->ms_t1_u_arr = NULL;
	}
	
	if (t1_v_arr != NULL) {
		ms->ms_t1_v_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t1_v_arr, _len_t1_v_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t1_v_arr);
		ocalloc_size -= _len_t1_v_arr;
	} else {
		ms->ms_t1_v_arr = NULL;
	}
	
	if (t2_u_arr != NULL) {
		ms->ms_t2_u_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t2_u_arr, _len_t2_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t2_u_arr);
		ocalloc_size -= _len_t2_u_arr;
	} else {
		ms->ms_t2_u_arr = NULL;
	}
	
	if (t2_v_arr != NULL) {
		ms->ms_t2_v_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, t2_v_arr, _len_t2_v_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_t2_v_arr);
		ocalloc_size -= _len_t2_v_arr;
	} else {
		ms->ms_t2_v_arr = NULL;
	}
	
	ms->ms_pair_count = pair_count;
	ms->ms_rand_size = rand_size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_retrieve_encrypted_doc(const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_del_id = del_id_len;
	size_t _len_encrypted_content = maxLen;
	size_t _len_length_content = int_len * sizeof(int);

	ms_ocall_retrieve_encrypted_doc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_retrieve_encrypted_doc_t);
	void *__tmp = NULL;

	void *__tmp_encrypted_content = NULL;
	void *__tmp_length_content = NULL;

	CHECK_ENCLAVE_POINTER(del_id, _len_del_id);
	CHECK_ENCLAVE_POINTER(encrypted_content, _len_encrypted_content);
	CHECK_ENCLAVE_POINTER(length_content, _len_length_content);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (del_id != NULL) ? _len_del_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (encrypted_content != NULL) ? _len_encrypted_content : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (length_content != NULL) ? _len_length_content : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_retrieve_encrypted_doc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_retrieve_encrypted_doc_t));
	ocalloc_size -= sizeof(ms_ocall_retrieve_encrypted_doc_t);

	if (del_id != NULL) {
		ms->ms_del_id = (const char*)__tmp;
		if (_len_del_id % sizeof(*del_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, del_id, _len_del_id)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_del_id);
		ocalloc_size -= _len_del_id;
	} else {
		ms->ms_del_id = NULL;
	}
	
	ms->ms_del_id_len = del_id_len;
	if (encrypted_content != NULL) {
		ms->ms_encrypted_content = (unsigned char*)__tmp;
		__tmp_encrypted_content = __tmp;
		if (_len_encrypted_content % sizeof(*encrypted_content) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_encrypted_content, 0, _len_encrypted_content);
		__tmp = (void *)((size_t)__tmp + _len_encrypted_content);
		ocalloc_size -= _len_encrypted_content;
	} else {
		ms->ms_encrypted_content = NULL;
	}
	
	ms->ms_maxLen = maxLen;
	if (length_content != NULL) {
		ms->ms_length_content = (int*)__tmp;
		__tmp_length_content = __tmp;
		if (_len_length_content % sizeof(*length_content) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_length_content, 0, _len_length_content);
		__tmp = (void *)((size_t)__tmp + _len_length_content);
		ocalloc_size -= _len_length_content;
	} else {
		ms->ms_length_content = NULL;
	}
	
	ms->ms_int_len = int_len;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (encrypted_content) {
			if (memcpy_s((void*)encrypted_content, _len_encrypted_content, __tmp_encrypted_content, _len_encrypted_content)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (length_content) {
			if (memcpy_s((void*)length_content, _len_length_content, __tmp_length_content, _len_length_content)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_del_encrypted_doc(const char* del_id, size_t del_id_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_del_id = del_id_len;

	ms_ocall_del_encrypted_doc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_del_encrypted_doc_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(del_id, _len_del_id);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (del_id != NULL) ? _len_del_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_del_encrypted_doc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_del_encrypted_doc_t));
	ocalloc_size -= sizeof(ms_ocall_del_encrypted_doc_t);

	if (del_id != NULL) {
		ms->ms_del_id = (const char*)__tmp;
		if (_len_del_id % sizeof(*del_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, del_id, _len_del_id)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_del_id);
		ocalloc_size -= _len_del_id;
	} else {
		ms->ms_del_id = NULL;
	}
	
	ms->ms_del_id_len = del_id_len;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_retrieve_M_c(unsigned char* _u_prime, size_t _u_prime_size, unsigned char* _v_prime, size_t maxLen, int* _v_prime_size, size_t int_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__u_prime = _u_prime_size;
	size_t _len__v_prime = maxLen;
	size_t _len__v_prime_size = int_len * sizeof(int);

	ms_ocall_retrieve_M_c_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_retrieve_M_c_t);
	void *__tmp = NULL;

	void *__tmp__v_prime = NULL;
	void *__tmp__v_prime_size = NULL;

	CHECK_ENCLAVE_POINTER(_u_prime, _len__u_prime);
	CHECK_ENCLAVE_POINTER(_v_prime, _len__v_prime);
	CHECK_ENCLAVE_POINTER(_v_prime_size, _len__v_prime_size);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_u_prime != NULL) ? _len__u_prime : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_v_prime != NULL) ? _len__v_prime : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_v_prime_size != NULL) ? _len__v_prime_size : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_retrieve_M_c_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_retrieve_M_c_t));
	ocalloc_size -= sizeof(ms_ocall_retrieve_M_c_t);

	if (_u_prime != NULL) {
		ms->ms__u_prime = (unsigned char*)__tmp;
		if (_len__u_prime % sizeof(*_u_prime) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, _u_prime, _len__u_prime)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len__u_prime);
		ocalloc_size -= _len__u_prime;
	} else {
		ms->ms__u_prime = NULL;
	}
	
	ms->ms__u_prime_size = _u_prime_size;
	if (_v_prime != NULL) {
		ms->ms__v_prime = (unsigned char*)__tmp;
		__tmp__v_prime = __tmp;
		if (_len__v_prime % sizeof(*_v_prime) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp__v_prime, 0, _len__v_prime);
		__tmp = (void *)((size_t)__tmp + _len__v_prime);
		ocalloc_size -= _len__v_prime;
	} else {
		ms->ms__v_prime = NULL;
	}
	
	ms->ms_maxLen = maxLen;
	if (_v_prime_size != NULL) {
		ms->ms__v_prime_size = (int*)__tmp;
		__tmp__v_prime_size = __tmp;
		if (_len__v_prime_size % sizeof(*_v_prime_size) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp__v_prime_size, 0, _len__v_prime_size);
		__tmp = (void *)((size_t)__tmp + _len__v_prime_size);
		ocalloc_size -= _len__v_prime_size;
	} else {
		ms->ms__v_prime_size = NULL;
	}
	
	ms->ms_int_len = int_len;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (_v_prime) {
			if (memcpy_s((void*)_v_prime, _len__v_prime, __tmp__v_prime, _len__v_prime)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (_v_prime_size) {
			if (memcpy_s((void*)_v_prime_size, _len__v_prime_size, __tmp__v_prime_size, _len__v_prime_size)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_del_M_c_value(const unsigned char* _u_prime, size_t _u_prime_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len__u_prime = _u_prime_size;

	ms_ocall_del_M_c_value_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_del_M_c_value_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(_u_prime, _len__u_prime);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (_u_prime != NULL) ? _len__u_prime : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_del_M_c_value_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_del_M_c_value_t));
	ocalloc_size -= sizeof(ms_ocall_del_M_c_value_t);

	if (_u_prime != NULL) {
		ms->ms__u_prime = (const unsigned char*)__tmp;
		if (_len__u_prime % sizeof(*_u_prime) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, _u_prime, _len__u_prime)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len__u_prime);
		ocalloc_size -= _len__u_prime;
	} else {
		ms->ms__u_prime = NULL;
	}
	
	ms->ms__u_prime_size = _u_prime_size;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_query_tokens_entries(const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_Q_w_u_arr = pair_count * rand_size;
	size_t _len_Q_w_id_arr = pair_count * rand_size;

	ms_ocall_query_tokens_entries_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_query_tokens_entries_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(Q_w_u_arr, _len_Q_w_u_arr);
	CHECK_ENCLAVE_POINTER(Q_w_id_arr, _len_Q_w_id_arr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (Q_w_u_arr != NULL) ? _len_Q_w_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (Q_w_id_arr != NULL) ? _len_Q_w_id_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_query_tokens_entries_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_query_tokens_entries_t));
	ocalloc_size -= sizeof(ms_ocall_query_tokens_entries_t);

	if (Q_w_u_arr != NULL) {
		ms->ms_Q_w_u_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, Q_w_u_arr, _len_Q_w_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_Q_w_u_arr);
		ocalloc_size -= _len_Q_w_u_arr;
	} else {
		ms->ms_Q_w_u_arr = NULL;
	}
	
	if (Q_w_id_arr != NULL) {
		ms->ms_Q_w_id_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, Q_w_id_arr, _len_Q_w_id_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_Q_w_id_arr);
		ocalloc_size -= _len_Q_w_id_arr;
	} else {
		ms->ms_Q_w_id_arr = NULL;
	}
	
	ms->ms_pair_count = pair_count;
	ms->ms_rand_size = rand_size;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_retrieve_VGama(unsigned char* L_text, int L_length, unsigned char* V_text, int V_length, unsigned char* Gama_text, int Gama_length)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_L_text = L_length;
	size_t _len_V_text = V_length;
	size_t _len_Gama_text = Gama_length;

	ms_ocall_retrieve_VGama_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_retrieve_VGama_t);
	void *__tmp = NULL;

	void *__tmp_V_text = NULL;
	void *__tmp_Gama_text = NULL;

	CHECK_ENCLAVE_POINTER(L_text, _len_L_text);
	CHECK_ENCLAVE_POINTER(V_text, _len_V_text);
	CHECK_ENCLAVE_POINTER(Gama_text, _len_Gama_text);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (L_text != NULL) ? _len_L_text : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (V_text != NULL) ? _len_V_text : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (Gama_text != NULL) ? _len_Gama_text : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_retrieve_VGama_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_retrieve_VGama_t));
	ocalloc_size -= sizeof(ms_ocall_retrieve_VGama_t);

	if (L_text != NULL) {
		ms->ms_L_text = (unsigned char*)__tmp;
		if (_len_L_text % sizeof(*L_text) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, L_text, _len_L_text)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_L_text);
		ocalloc_size -= _len_L_text;
	} else {
		ms->ms_L_text = NULL;
	}
	
	ms->ms_L_length = L_length;
	if (V_text != NULL) {
		ms->ms_V_text = (unsigned char*)__tmp;
		__tmp_V_text = __tmp;
		if (_len_V_text % sizeof(*V_text) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_V_text, 0, _len_V_text);
		__tmp = (void *)((size_t)__tmp + _len_V_text);
		ocalloc_size -= _len_V_text;
	} else {
		ms->ms_V_text = NULL;
	}
	
	ms->ms_V_length = V_length;
	if (Gama_text != NULL) {
		ms->ms_Gama_text = (unsigned char*)__tmp;
		__tmp_Gama_text = __tmp;
		if (_len_Gama_text % sizeof(*Gama_text) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_Gama_text, 0, _len_Gama_text);
		__tmp = (void *)((size_t)__tmp + _len_Gama_text);
		ocalloc_size -= _len_Gama_text;
	} else {
		ms->ms_Gama_text = NULL;
	}
	
	ms->ms_Gama_length = Gama_length;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (V_text) {
			if (memcpy_s((void*)V_text, _len_V_text, __tmp_V_text, _len_V_text)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (Gama_text) {
			if (memcpy_s((void*)Gama_text, _len_Gama_text, __tmp_Gama_text, _len_Gama_text)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_receive_VxGamaX(unsigned char* vx_text, int vx_length, unsigned char* gamax_plain, int gamax_plain_len, int vi)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_vx_text = vx_length;
	size_t _len_gamax_plain = gamax_plain_len;

	ms_ocall_receive_VxGamaX_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_receive_VxGamaX_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(vx_text, _len_vx_text);
	CHECK_ENCLAVE_POINTER(gamax_plain, _len_gamax_plain);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (vx_text != NULL) ? _len_vx_text : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (gamax_plain != NULL) ? _len_gamax_plain : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_receive_VxGamaX_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_receive_VxGamaX_t));
	ocalloc_size -= sizeof(ms_ocall_receive_VxGamaX_t);

	if (vx_text != NULL) {
		ms->ms_vx_text = (unsigned char*)__tmp;
		if (_len_vx_text % sizeof(*vx_text) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, vx_text, _len_vx_text)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_vx_text);
		ocalloc_size -= _len_vx_text;
	} else {
		ms->ms_vx_text = NULL;
	}
	
	ms->ms_vx_length = vx_length;
	if (gamax_plain != NULL) {
		ms->ms_gamax_plain = (unsigned char*)__tmp;
		if (_len_gamax_plain % sizeof(*gamax_plain) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, gamax_plain, _len_gamax_plain)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_gamax_plain);
		ocalloc_size -= _len_gamax_plain;
	} else {
		ms->ms_gamax_plain = NULL;
	}
	
	ms->ms_gamax_plain_len = gamax_plain_len;
	ms->ms_vi = vi;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_receive_R(unsigned char* R, int R_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_R = R_len;

	ms_ocall_receive_R_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_receive_R_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(R, _len_R);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (R != NULL) ? _len_R : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_receive_R_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_receive_R_t));
	ocalloc_size -= sizeof(ms_ocall_receive_R_t);

	if (R != NULL) {
		ms->ms_R = (unsigned char*)__tmp;
		if (_len_R % sizeof(*R) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, R, _len_R)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_R);
		ocalloc_size -= _len_R;
	} else {
		ms->ms_R = NULL;
	}
	
	ms->ms_R_len = R_len;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_sendLVGAMA(unsigned char* L2, int L2_len, unsigned char* V2, int V2_len, unsigned char* gama_X2_plain, int gama_X2_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_L2 = L2_len;
	size_t _len_V2 = V2_len;
	size_t _len_gama_X2_plain = gama_X2_len;

	ms_ocall_sendLVGAMA_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_sendLVGAMA_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(L2, _len_L2);
	CHECK_ENCLAVE_POINTER(V2, _len_V2);
	CHECK_ENCLAVE_POINTER(gama_X2_plain, _len_gama_X2_plain);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (L2 != NULL) ? _len_L2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (V2 != NULL) ? _len_V2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (gama_X2_plain != NULL) ? _len_gama_X2_plain : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_sendLVGAMA_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_sendLVGAMA_t));
	ocalloc_size -= sizeof(ms_ocall_sendLVGAMA_t);

	if (L2 != NULL) {
		ms->ms_L2 = (unsigned char*)__tmp;
		if (_len_L2 % sizeof(*L2) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, L2, _len_L2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_L2);
		ocalloc_size -= _len_L2;
	} else {
		ms->ms_L2 = NULL;
	}
	
	ms->ms_L2_len = L2_len;
	if (V2 != NULL) {
		ms->ms_V2 = (unsigned char*)__tmp;
		if (_len_V2 % sizeof(*V2) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, V2, _len_V2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_V2);
		ocalloc_size -= _len_V2;
	} else {
		ms->ms_V2 = NULL;
	}
	
	ms->ms_V2_len = V2_len;
	if (gama_X2_plain != NULL) {
		ms->ms_gama_X2_plain = (unsigned char*)__tmp;
		if (_len_gama_X2_plain % sizeof(*gama_X2_plain) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, gama_X2_plain, _len_gama_X2_plain)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_gama_X2_plain);
		ocalloc_size -= _len_gama_X2_plain;
	} else {
		ms->ms_gama_X2_plain = NULL;
	}
	
	ms->ms_gama_X2_len = gama_X2_len;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_retrieve_PKi(unsigned char* Addr, int addr_len, unsigned char* PKi, int PK_len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_Addr = addr_len;
	size_t _len_PKi = PK_len;

	ms_ocall_retrieve_PKi_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_retrieve_PKi_t);
	void *__tmp = NULL;

	void *__tmp_PKi = NULL;

	CHECK_ENCLAVE_POINTER(Addr, _len_Addr);
	CHECK_ENCLAVE_POINTER(PKi, _len_PKi);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (Addr != NULL) ? _len_Addr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (PKi != NULL) ? _len_PKi : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_retrieve_PKi_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_retrieve_PKi_t));
	ocalloc_size -= sizeof(ms_ocall_retrieve_PKi_t);

	if (Addr != NULL) {
		ms->ms_Addr = (unsigned char*)__tmp;
		if (_len_Addr % sizeof(*Addr) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, Addr, _len_Addr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_Addr);
		ocalloc_size -= _len_Addr;
	} else {
		ms->ms_Addr = NULL;
	}
	
	ms->ms_addr_len = addr_len;
	if (PKi != NULL) {
		ms->ms_PKi = (unsigned char*)__tmp;
		__tmp_PKi = __tmp;
		if (_len_PKi % sizeof(*PKi) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_PKi, 0, _len_PKi);
		__tmp = (void *)((size_t)__tmp + _len_PKi);
		ocalloc_size -= _len_PKi;
	} else {
		ms->ms_PKi = NULL;
	}
	
	ms->ms_PK_len = PK_len;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (PKi) {
			if (memcpy_s((void*)PKi, _len_PKi, __tmp_PKi, _len_PKi)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_transfer_uv_pairs(const void* u_arr, const void* v_arr, int pair_count, int rand_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_u_arr = pair_count * rand_size;
	size_t _len_v_arr = pair_count * rand_size;

	ms_ocall_transfer_uv_pairs_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_transfer_uv_pairs_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(u_arr, _len_u_arr);
	CHECK_ENCLAVE_POINTER(v_arr, _len_v_arr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (u_arr != NULL) ? _len_u_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (v_arr != NULL) ? _len_v_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_transfer_uv_pairs_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_transfer_uv_pairs_t));
	ocalloc_size -= sizeof(ms_ocall_transfer_uv_pairs_t);

	if (u_arr != NULL) {
		ms->ms_u_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, u_arr, _len_u_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_u_arr);
		ocalloc_size -= _len_u_arr;
	} else {
		ms->ms_u_arr = NULL;
	}
	
	if (v_arr != NULL) {
		ms->ms_v_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, v_arr, _len_v_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_v_arr);
		ocalloc_size -= _len_v_arr;
	} else {
		ms->ms_v_arr = NULL;
	}
	
	ms->ms_pair_count = pair_count;
	ms->ms_rand_size = rand_size;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

