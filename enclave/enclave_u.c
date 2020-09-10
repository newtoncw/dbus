#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_session_request_t {
	char* ms_uid;
	size_t ms_uid_len;
	sgx_dh_msg1_t* ms_dh_msg1;
	sgx_status_t* ms_ret;
} ms_ecall_session_request_t;

typedef struct ms_ecall_exchange_report_t {
	char* ms_uid;
	size_t ms_uid_len;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	sgx_status_t* ms_ret;
} ms_ecall_exchange_report_t;

typedef struct ms_ecall_init_session_t {
	sgx_dh_session_t* ms_session;
	sgx_status_t* ms_ret;
} ms_ecall_init_session_t;

typedef struct ms_ecall_initiator_proc_msg1_t {
	char* ms_uid;
	size_t ms_uid_len;
	const sgx_dh_msg1_t* ms_msg1;
	sgx_dh_msg2_t* ms_msg2;
	sgx_dh_session_t* ms_dh_session;
	sgx_status_t* ms_ret;
} ms_ecall_initiator_proc_msg1_t;

typedef struct ms_ecall_initiator_proc_msg3_t {
	char* ms_uid;
	size_t ms_uid_len;
	const sgx_dh_msg3_t* ms_msg3;
	sgx_dh_session_t* ms_dh_session;
	sgx_status_t* ms_ret;
} ms_ecall_initiator_proc_msg3_t;

typedef struct ms_ecall_close_session_t {
	char* ms_uid;
	size_t ms_uid_len;
} ms_ecall_close_session_t;

typedef struct ms_ecall_encrypt_t {
	char* ms_uid;
	size_t ms_uid_len;
	uint8_t* ms_message;
	size_t ms_message_size;
	sgx_aes_gcm_data_t* ms_response;
	size_t ms_response_size;
	sgx_status_t* ms_ret;
} ms_ecall_encrypt_t;

typedef struct ms_ecall_decrypt_t {
	char* ms_uid;
	size_t ms_uid_len;
	sgx_aes_gcm_data_t* ms_message;
	size_t ms_message_size;
	uint8_t* ms_response;
	size_t ms_response_size;
	sgx_status_t* ms_ret;
} ms_ecall_decrypt_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_session_request(sgx_enclave_id_t eid, char* uid, sgx_dh_msg1_t* dh_msg1, sgx_status_t* ret)
{
	sgx_status_t status;
	ms_ecall_session_request_t ms;
	ms.ms_uid = uid;
	ms.ms_uid_len = uid ? strlen(uid) + 1 : 0;
	ms.ms_dh_msg1 = dh_msg1;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_exchange_report(sgx_enclave_id_t eid, char* uid, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, sgx_status_t* ret)
{
	sgx_status_t status;
	ms_ecall_exchange_report_t ms;
	ms.ms_uid = uid;
	ms.ms_uid_len = uid ? strlen(uid) + 1 : 0;
	ms.ms_dh_msg2 = dh_msg2;
	ms.ms_dh_msg3 = dh_msg3;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_init_session(sgx_enclave_id_t eid, sgx_dh_session_t* session, sgx_status_t* ret)
{
	sgx_status_t status;
	ms_ecall_init_session_t ms;
	ms.ms_session = session;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_initiator_proc_msg1(sgx_enclave_id_t eid, char* uid, const sgx_dh_msg1_t* msg1, sgx_dh_msg2_t* msg2, sgx_dh_session_t* dh_session, sgx_status_t* ret)
{
	sgx_status_t status;
	ms_ecall_initiator_proc_msg1_t ms;
	ms.ms_uid = uid;
	ms.ms_uid_len = uid ? strlen(uid) + 1 : 0;
	ms.ms_msg1 = msg1;
	ms.ms_msg2 = msg2;
	ms.ms_dh_session = dh_session;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_initiator_proc_msg3(sgx_enclave_id_t eid, char* uid, const sgx_dh_msg3_t* msg3, sgx_dh_session_t* dh_session, sgx_status_t* ret)
{
	sgx_status_t status;
	ms_ecall_initiator_proc_msg3_t ms;
	ms.ms_uid = uid;
	ms.ms_uid_len = uid ? strlen(uid) + 1 : 0;
	ms.ms_msg3 = msg3;
	ms.ms_dh_session = dh_session;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_close_session(sgx_enclave_id_t eid, char* uid)
{
	sgx_status_t status;
	ms_ecall_close_session_t ms;
	ms.ms_uid = uid;
	ms.ms_uid_len = uid ? strlen(uid) + 1 : 0;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_encrypt(sgx_enclave_id_t eid, char* uid, uint8_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size, sgx_status_t* ret)
{
	sgx_status_t status;
	ms_ecall_encrypt_t ms;
	ms.ms_uid = uid;
	ms.ms_uid_len = uid ? strlen(uid) + 1 : 0;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_response = response;
	ms.ms_response_size = response_size;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t ecall_decrypt(sgx_enclave_id_t eid, char* uid, sgx_aes_gcm_data_t* message, size_t message_size, uint8_t* response, size_t response_size, sgx_status_t* ret)
{
	sgx_status_t status;
	ms_ecall_decrypt_t ms;
	ms.ms_uid = uid;
	ms.ms_uid_len = uid ? strlen(uid) + 1 : 0;
	ms.ms_message = message;
	ms.ms_message_size = message_size;
	ms.ms_response = response;
	ms.ms_response_size = response_size;
	ms.ms_ret = ret;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, &ms);
	return status;
}

