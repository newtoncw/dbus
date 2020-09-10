#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_eid.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_session_request(char* uid, sgx_dh_msg1_t* dh_msg1, sgx_status_t* ret);
void ecall_exchange_report(char* uid, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, sgx_status_t* ret);
void ecall_init_session(sgx_dh_session_t* session, sgx_status_t* ret);
void ecall_initiator_proc_msg1(char* uid, const sgx_dh_msg1_t* msg1, sgx_dh_msg2_t* msg2, sgx_dh_session_t* dh_session, sgx_status_t* ret);
void ecall_initiator_proc_msg3(char* uid, const sgx_dh_msg3_t* msg3, sgx_dh_session_t* dh_session, sgx_status_t* ret);
void ecall_close_session(char* uid);
void ecall_encrypt(char* uid, uint8_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size, sgx_status_t* ret);
void ecall_decrypt(char* uid, sgx_aes_gcm_data_t* message, size_t message_size, uint8_t* response, size_t response_size, sgx_status_t* ret);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
