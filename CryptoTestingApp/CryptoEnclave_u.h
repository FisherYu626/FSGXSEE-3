#ifndef CRYPTOENCLAVE_U_H__
#define CRYPTOENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_TRANSFER_ENCRYPTED_ENTRIES_DEFINED__
#define OCALL_TRANSFER_ENCRYPTED_ENTRIES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_transfer_encrypted_entries, (const void* t1_u_arr, const void* t1_v_arr, const void* t2_u_arr, const void* t2_v_arr, int pair_count, int rand_size));
#endif
#ifndef OCALL_RETRIEVE_ENCRYPTED_DOC_DEFINED__
#define OCALL_RETRIEVE_ENCRYPTED_DOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_retrieve_encrypted_doc, (const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len));
#endif
#ifndef OCALL_DEL_ENCRYPTED_DOC_DEFINED__
#define OCALL_DEL_ENCRYPTED_DOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_del_encrypted_doc, (const char* del_id, size_t del_id_len));
#endif
#ifndef OCALL_RETRIEVE_M_C_DEFINED__
#define OCALL_RETRIEVE_M_C_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_retrieve_M_c, (unsigned char* _u_prime, size_t _u_prime_size, unsigned char* _v_prime, size_t maxLen, int* _v_prime_size, size_t int_len));
#endif
#ifndef OCALL_DEL_M_C_VALUE_DEFINED__
#define OCALL_DEL_M_C_VALUE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_del_M_c_value, (const unsigned char* _u_prime, size_t _u_prime_size));
#endif
#ifndef OCALL_QUERY_TOKENS_ENTRIES_DEFINED__
#define OCALL_QUERY_TOKENS_ENTRIES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_query_tokens_entries, (const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size));
#endif
#ifndef OCALL_RETRIEVE_VGAMA_DEFINED__
#define OCALL_RETRIEVE_VGAMA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_retrieve_VGama, (unsigned char* L_text, int L_length, unsigned char* V_text, int V_length, unsigned char* Gama_text, int Gama_length));
#endif
#ifndef OCALL_RECEIVE_VXGAMAX_DEFINED__
#define OCALL_RECEIVE_VXGAMAX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_receive_VxGamaX, (unsigned char* vx_text, int vx_length, unsigned char* gamax_plain, int gamax_plain_len, int vi));
#endif
#ifndef OCALL_RECEIVE_R_DEFINED__
#define OCALL_RECEIVE_R_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_receive_R, (unsigned char* R, int R_len));
#endif
#ifndef OCALL_SENDLVGAMA_DEFINED__
#define OCALL_SENDLVGAMA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_sendLVGAMA, (unsigned char* L2, int L2_len, unsigned char* V2, int V2_len, unsigned char* gama_X2_plain, int gama_X2_len));
#endif
#ifndef OCALL_RETRIEVE_PKI_DEFINED__
#define OCALL_RETRIEVE_PKI_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_retrieve_PKi, (unsigned char* Addr, int addr_len, unsigned char* PKi, int PK_len));
#endif
#ifndef OCALL_TRANSFER_UV_PAIRS_DEFINED__
#define OCALL_TRANSFER_UV_PAIRS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_transfer_uv_pairs, (const void* u_arr, const void* v_arr, int pair_count, int rand_size));
#endif
#ifndef OCALL_RETRIEVE_V_FROMT1_DEFINED__
#define OCALL_RETRIEVE_V_FROMT1_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_Retrieve_V_FromT1, (unsigned char* u, size_t u_len, unsigned char* v, size_t v_len, int* content_length, size_t int_len));
#endif
#ifndef OCALL_TRANSFER_V_DEFINED__
#define OCALL_TRANSFER_V_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_transfer_V, (const void* v_arr, int pair_count, int rand_size));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid, unsigned char* keyF1, unsigned char* keyF2, unsigned char* keyF3, size_t len);
sgx_status_t ecall_addDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length, char* content, int content_length);
sgx_status_t ecall_delDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length);
sgx_status_t ecall_search(sgx_enclave_id_t eid, const char* keyword, size_t len);
sgx_status_t ecall_printHelloWorld(sgx_enclave_id_t eid);
sgx_status_t ecall_InsertVct(sgx_enclave_id_t eid, int vword, int c, int t);
sgx_status_t ecall_searchToken(sgx_enclave_id_t eid, unsigned char* token, int token_len);
sgx_status_t ecall_search_tkq(sgx_enclave_id_t eid, unsigned char* token, int token_len);
sgx_status_t ecall_verifyIDEnc(sgx_enclave_id_t eid, unsigned char* ID, size_t len);
sgx_status_t ecall_SendOpIdN(sgx_enclave_id_t eid, int op, unsigned char* IdN, int len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
