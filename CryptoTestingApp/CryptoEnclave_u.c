#include "CryptoEnclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_transfer_encrypted_entries(void* pms)
{
	ms_ocall_transfer_encrypted_entries_t* ms = SGX_CAST(ms_ocall_transfer_encrypted_entries_t*, pms);
	ocall_transfer_encrypted_entries(ms->ms_t1_u_arr, ms->ms_t1_v_arr, ms->ms_t2_u_arr, ms->ms_t2_v_arr, ms->ms_pair_count, ms->ms_rand_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_encrypted_doc(void* pms)
{
	ms_ocall_retrieve_encrypted_doc_t* ms = SGX_CAST(ms_ocall_retrieve_encrypted_doc_t*, pms);
	ocall_retrieve_encrypted_doc(ms->ms_del_id, ms->ms_del_id_len, ms->ms_encrypted_content, ms->ms_maxLen, ms->ms_length_content, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_del_encrypted_doc(void* pms)
{
	ms_ocall_del_encrypted_doc_t* ms = SGX_CAST(ms_ocall_del_encrypted_doc_t*, pms);
	ocall_del_encrypted_doc(ms->ms_del_id, ms->ms_del_id_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_M_c(void* pms)
{
	ms_ocall_retrieve_M_c_t* ms = SGX_CAST(ms_ocall_retrieve_M_c_t*, pms);
	ocall_retrieve_M_c(ms->ms__u_prime, ms->ms__u_prime_size, ms->ms__v_prime, ms->ms_maxLen, ms->ms__v_prime_size, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_del_M_c_value(void* pms)
{
	ms_ocall_del_M_c_value_t* ms = SGX_CAST(ms_ocall_del_M_c_value_t*, pms);
	ocall_del_M_c_value(ms->ms__u_prime, ms->ms__u_prime_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_query_tokens_entries(void* pms)
{
	ms_ocall_query_tokens_entries_t* ms = SGX_CAST(ms_ocall_query_tokens_entries_t*, pms);
	ocall_query_tokens_entries(ms->ms_Q_w_u_arr, ms->ms_Q_w_id_arr, ms->ms_pair_count, ms->ms_rand_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_VGama(void* pms)
{
	ms_ocall_retrieve_VGama_t* ms = SGX_CAST(ms_ocall_retrieve_VGama_t*, pms);
	ocall_retrieve_VGama(ms->ms_L_text, ms->ms_L_length, ms->ms_V_text, ms->ms_V_length, ms->ms_Gama_text, ms->ms_Gama_length);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_receive_VxGamaX(void* pms)
{
	ms_ocall_receive_VxGamaX_t* ms = SGX_CAST(ms_ocall_receive_VxGamaX_t*, pms);
	ocall_receive_VxGamaX(ms->ms_vx_text, ms->ms_vx_length, ms->ms_gamax_plain, ms->ms_gamax_plain_len, ms->ms_vi);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_receive_R(void* pms)
{
	ms_ocall_receive_R_t* ms = SGX_CAST(ms_ocall_receive_R_t*, pms);
	ocall_receive_R(ms->ms_R, ms->ms_R_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_sendLVGAMA(void* pms)
{
	ms_ocall_sendLVGAMA_t* ms = SGX_CAST(ms_ocall_sendLVGAMA_t*, pms);
	ocall_sendLVGAMA(ms->ms_L2, ms->ms_L2_len, ms->ms_V2, ms->ms_V2_len, ms->ms_gama_X2_plain, ms->ms_gama_X2_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_PKi(void* pms)
{
	ms_ocall_retrieve_PKi_t* ms = SGX_CAST(ms_ocall_retrieve_PKi_t*, pms);
	ocall_retrieve_PKi(ms->ms_Addr, ms->ms_addr_len, ms->ms_PKi, ms->ms_PK_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_transfer_uv_pairs(void* pms)
{
	ms_ocall_transfer_uv_pairs_t* ms = SGX_CAST(ms_ocall_transfer_uv_pairs_t*, pms);
	ocall_transfer_uv_pairs(ms->ms_u_arr, ms->ms_v_arr, ms->ms_pair_count, ms->ms_rand_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[18];
} ocall_table_CryptoEnclave = {
	18,
	{
		(void*)CryptoEnclave_ocall_print_string,
		(void*)CryptoEnclave_ocall_transfer_encrypted_entries,
		(void*)CryptoEnclave_ocall_retrieve_encrypted_doc,
		(void*)CryptoEnclave_ocall_del_encrypted_doc,
		(void*)CryptoEnclave_ocall_retrieve_M_c,
		(void*)CryptoEnclave_ocall_del_M_c_value,
		(void*)CryptoEnclave_ocall_query_tokens_entries,
		(void*)CryptoEnclave_ocall_retrieve_VGama,
		(void*)CryptoEnclave_ocall_receive_VxGamaX,
		(void*)CryptoEnclave_ocall_receive_R,
		(void*)CryptoEnclave_ocall_sendLVGAMA,
		(void*)CryptoEnclave_ocall_retrieve_PKi,
		(void*)CryptoEnclave_ocall_transfer_uv_pairs,
		(void*)CryptoEnclave_sgx_oc_cpuidex,
		(void*)CryptoEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_init(sgx_enclave_id_t eid, unsigned char* keyF1, unsigned char* keyF2, unsigned char* keyF3, size_t len)
{
	sgx_status_t status;
	ms_ecall_init_t ms;
	ms.ms_keyF1 = keyF1;
	ms.ms_keyF2 = keyF2;
	ms.ms_keyF3 = keyF3;
	ms.ms_len = len;
	status = sgx_ecall(eid, 0, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_addDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length, char* content, int content_length)
{
	sgx_status_t status;
	ms_ecall_addDoc_t ms;
	ms.ms_doc_id = doc_id;
	ms.ms_id_length = id_length;
	ms.ms_content = content;
	ms.ms_content_length = content_length;
	status = sgx_ecall(eid, 1, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_delDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length)
{
	sgx_status_t status;
	ms_ecall_delDoc_t ms;
	ms.ms_doc_id = doc_id;
	ms.ms_id_length = id_length;
	status = sgx_ecall(eid, 2, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_search(sgx_enclave_id_t eid, const char* keyword, size_t len)
{
	sgx_status_t status;
	ms_ecall_search_t ms;
	ms.ms_keyword = keyword;
	ms.ms_len = len;
	status = sgx_ecall(eid, 3, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_printHelloWorld(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_CryptoEnclave, NULL);
	return status;
}

sgx_status_t ecall_InsertVct(sgx_enclave_id_t eid, int vword, int c, int t)
{
	sgx_status_t status;
	ms_ecall_InsertVct_t ms;
	ms.ms_vword = vword;
	ms.ms_c = c;
	ms.ms_t = t;
	status = sgx_ecall(eid, 5, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_searchToken(sgx_enclave_id_t eid, unsigned char* token, int token_len)
{
	sgx_status_t status;
	ms_ecall_searchToken_t ms;
	ms.ms_token = token;
	ms.ms_token_len = token_len;
	status = sgx_ecall(eid, 6, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_search_tkq(sgx_enclave_id_t eid, unsigned char* token, int token_len)
{
	sgx_status_t status;
	ms_ecall_search_tkq_t ms;
	ms.ms_token = token;
	ms.ms_token_len = token_len;
	status = sgx_ecall(eid, 7, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_verifyIDEnc(sgx_enclave_id_t eid, unsigned char* ID, size_t len)
{
	sgx_status_t status;
	ms_ecall_verifyIDEnc_t ms;
	ms.ms_ID = ID;
	ms.ms_len = len;
	status = sgx_ecall(eid, 8, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_SendOpIdN(sgx_enclave_id_t eid, int op, unsigned char* IdN, int len)
{
	sgx_status_t status;
	ms_ecall_SendOpIdN_t ms;
	ms.ms_op = op;
	ms.ms_IdN = IdN;
	ms.ms_len = len;
	status = sgx_ecall(eid, 9, &ocall_table_CryptoEnclave, &ms);
	return status;
}

