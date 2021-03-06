#ifndef CRYPTOENCLAVE_T_H__
#define CRYPTOENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_init(unsigned char* keyF1, unsigned char* keyF2, unsigned char* keyF3, size_t len);
void ecall_addDoc(char* doc_id, size_t id_length, char* content, int content_length);
void ecall_delDoc(char* doc_id, size_t id_length);
void ecall_search(const char* keyword, size_t len);
void ecall_printHelloWorld(void);
void ecall_InsertVct(int vword, int c, int t);
void ecall_searchToken(unsigned char* token, int token_len);
void ecall_search_tkq(unsigned char* token, int token_len);
void ecall_verifyIDEnc(unsigned char* ID, size_t len);
void ecall_SendOpIdN(int op, unsigned char* IdN, int len);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_transfer_encrypted_entries(const void* t1_u_arr, const void* t1_v_arr, const void* t2_u_arr, const void* t2_v_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL ocall_retrieve_encrypted_doc(const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len);
sgx_status_t SGX_CDECL ocall_del_encrypted_doc(const char* del_id, size_t del_id_len);
sgx_status_t SGX_CDECL ocall_retrieve_M_c(unsigned char* _u_prime, size_t _u_prime_size, unsigned char* _v_prime, size_t maxLen, int* _v_prime_size, size_t int_len);
sgx_status_t SGX_CDECL ocall_del_M_c_value(const unsigned char* _u_prime, size_t _u_prime_size);
sgx_status_t SGX_CDECL ocall_query_tokens_entries(const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL ocall_retrieve_VGama(unsigned char* L_text, int L_length, unsigned char* V_text, int V_length, unsigned char* Gama_text, int Gama_length);
sgx_status_t SGX_CDECL ocall_receive_VxGamaX(unsigned char* vx_text, int vx_length, unsigned char* gamax_plain, int gamax_plain_len, int vi);
sgx_status_t SGX_CDECL ocall_receive_R(unsigned char* R, int R_len);
sgx_status_t SGX_CDECL ocall_sendLVGAMA(unsigned char* L2, int L2_len, unsigned char* V2, int V2_len, unsigned char* gama_X2_plain, int gama_X2_len);
sgx_status_t SGX_CDECL ocall_retrieve_PKi(unsigned char* Addr, int addr_len, unsigned char* PKi, int PK_len);
sgx_status_t SGX_CDECL ocall_transfer_uv_pairs(const void* u_arr, const void* v_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL ocall_Retrieve_V_FromT1(unsigned char* u, size_t u_len, unsigned char* v, size_t v_len, int* content_length, size_t int_len);
sgx_status_t SGX_CDECL ocall_transfer_V(const void* v_arr, int pair_count, int rand_size);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
