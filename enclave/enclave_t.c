#include "enclave_t.h"

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

static sgx_status_t SGX_CDECL sgx_ecall_session_request(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_session_request_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_session_request_t* ms = SGX_CAST(ms_ecall_session_request_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_uid = ms->ms_uid;
	size_t _len_uid = ms->ms_uid_len ;
	char* _in_uid = NULL;
	sgx_dh_msg1_t* _tmp_dh_msg1 = ms->ms_dh_msg1;
	size_t _len_dh_msg1 = sizeof(sgx_dh_msg1_t);
	sgx_dh_msg1_t* _in_dh_msg1 = NULL;
	sgx_status_t* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(sgx_status_t);
	sgx_status_t* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_dh_msg1, _len_dh_msg1);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_uid != NULL && _len_uid != 0) {
		_in_uid = (char*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_uid[_len_uid - 1] = '\0';
		if (_len_uid != strlen(_in_uid) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_dh_msg1 != NULL && _len_dh_msg1 != 0) {
		if ((_in_dh_msg1 = (sgx_dh_msg1_t*)malloc(_len_dh_msg1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg1, 0, _len_dh_msg1);
	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ((_in_ret = (sgx_status_t*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_session_request(_in_uid, _in_dh_msg1, _in_ret);
err:
	if (_in_uid) free(_in_uid);
	if (_in_dh_msg1) {
		if (memcpy_s(_tmp_dh_msg1, _len_dh_msg1, _in_dh_msg1, _len_dh_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_dh_msg1);
	}
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_exchange_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_exchange_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_exchange_report_t* ms = SGX_CAST(ms_ecall_exchange_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_uid = ms->ms_uid;
	size_t _len_uid = ms->ms_uid_len ;
	char* _in_uid = NULL;
	sgx_dh_msg2_t* _tmp_dh_msg2 = ms->ms_dh_msg2;
	size_t _len_dh_msg2 = sizeof(sgx_dh_msg2_t);
	sgx_dh_msg2_t* _in_dh_msg2 = NULL;
	sgx_dh_msg3_t* _tmp_dh_msg3 = ms->ms_dh_msg3;
	size_t _len_dh_msg3 = sizeof(sgx_dh_msg3_t);
	sgx_dh_msg3_t* _in_dh_msg3 = NULL;
	sgx_status_t* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(sgx_status_t);
	sgx_status_t* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_dh_msg2, _len_dh_msg2);
	CHECK_UNIQUE_POINTER(_tmp_dh_msg3, _len_dh_msg3);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_uid != NULL && _len_uid != 0) {
		_in_uid = (char*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_uid[_len_uid - 1] = '\0';
		if (_len_uid != strlen(_in_uid) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_dh_msg2 != NULL && _len_dh_msg2 != 0) {
		_in_dh_msg2 = (sgx_dh_msg2_t*)malloc(_len_dh_msg2);
		if (_in_dh_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dh_msg2, _len_dh_msg2, _tmp_dh_msg2, _len_dh_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dh_msg3 != NULL && _len_dh_msg3 != 0) {
		if ((_in_dh_msg3 = (sgx_dh_msg3_t*)malloc(_len_dh_msg3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg3, 0, _len_dh_msg3);
	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ((_in_ret = (sgx_status_t*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_exchange_report(_in_uid, _in_dh_msg2, _in_dh_msg3, _in_ret);
err:
	if (_in_uid) free(_in_uid);
	if (_in_dh_msg2) free(_in_dh_msg2);
	if (_in_dh_msg3) {
		if (memcpy_s(_tmp_dh_msg3, _len_dh_msg3, _in_dh_msg3, _len_dh_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_dh_msg3);
	}
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_init_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_init_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_init_session_t* ms = SGX_CAST(ms_ecall_init_session_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_session_t* _tmp_session = ms->ms_session;
	size_t _len_session = sizeof(sgx_dh_session_t);
	sgx_dh_session_t* _in_session = NULL;
	sgx_status_t* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(sgx_status_t);
	sgx_status_t* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_session, _len_session);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_session != NULL && _len_session != 0) {
		if ((_in_session = (sgx_dh_session_t*)malloc(_len_session)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_session, 0, _len_session);
	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ((_in_ret = (sgx_status_t*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_init_session(_in_session, _in_ret);
err:
	if (_in_session) {
		if (memcpy_s(_tmp_session, _len_session, _in_session, _len_session)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_session);
	}
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_initiator_proc_msg1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_initiator_proc_msg1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_initiator_proc_msg1_t* ms = SGX_CAST(ms_ecall_initiator_proc_msg1_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_uid = ms->ms_uid;
	size_t _len_uid = ms->ms_uid_len ;
	char* _in_uid = NULL;
	const sgx_dh_msg1_t* _tmp_msg1 = ms->ms_msg1;
	size_t _len_msg1 = sizeof(sgx_dh_msg1_t);
	sgx_dh_msg1_t* _in_msg1 = NULL;
	sgx_dh_msg2_t* _tmp_msg2 = ms->ms_msg2;
	size_t _len_msg2 = sizeof(sgx_dh_msg2_t);
	sgx_dh_msg2_t* _in_msg2 = NULL;
	sgx_dh_session_t* _tmp_dh_session = ms->ms_dh_session;
	size_t _len_dh_session = sizeof(sgx_dh_session_t);
	sgx_dh_session_t* _in_dh_session = NULL;
	sgx_status_t* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(sgx_status_t);
	sgx_status_t* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_msg1, _len_msg1);
	CHECK_UNIQUE_POINTER(_tmp_msg2, _len_msg2);
	CHECK_UNIQUE_POINTER(_tmp_dh_session, _len_dh_session);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_uid != NULL && _len_uid != 0) {
		_in_uid = (char*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_uid[_len_uid - 1] = '\0';
		if (_len_uid != strlen(_in_uid) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_msg1 != NULL && _len_msg1 != 0) {
		_in_msg1 = (sgx_dh_msg1_t*)malloc(_len_msg1);
		if (_in_msg1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s((void*)_in_msg1, _len_msg1, _tmp_msg1, _len_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_msg2 != NULL && _len_msg2 != 0) {
		if ((_in_msg2 = (sgx_dh_msg2_t*)malloc(_len_msg2)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_msg2, 0, _len_msg2);
	}
	if (_tmp_dh_session != NULL && _len_dh_session != 0) {
		_in_dh_session = (sgx_dh_session_t*)malloc(_len_dh_session);
		if (_in_dh_session == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dh_session, _len_dh_session, _tmp_dh_session, _len_dh_session)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ((_in_ret = (sgx_status_t*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_initiator_proc_msg1(_in_uid, (const sgx_dh_msg1_t*)_in_msg1, _in_msg2, _in_dh_session, _in_ret);
err:
	if (_in_uid) free(_in_uid);
	if (_in_msg1) free((void*)_in_msg1);
	if (_in_msg2) {
		if (memcpy_s(_tmp_msg2, _len_msg2, _in_msg2, _len_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_msg2);
	}
	if (_in_dh_session) {
		if (memcpy_s(_tmp_dh_session, _len_dh_session, _in_dh_session, _len_dh_session)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_dh_session);
	}
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_initiator_proc_msg3(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_initiator_proc_msg3_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_initiator_proc_msg3_t* ms = SGX_CAST(ms_ecall_initiator_proc_msg3_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_uid = ms->ms_uid;
	size_t _len_uid = ms->ms_uid_len ;
	char* _in_uid = NULL;
	const sgx_dh_msg3_t* _tmp_msg3 = ms->ms_msg3;
	size_t _len_msg3 = sizeof(sgx_dh_msg3_t);
	sgx_dh_msg3_t* _in_msg3 = NULL;
	sgx_dh_session_t* _tmp_dh_session = ms->ms_dh_session;
	size_t _len_dh_session = sizeof(sgx_dh_session_t);
	sgx_dh_session_t* _in_dh_session = NULL;
	sgx_status_t* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(sgx_status_t);
	sgx_status_t* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_msg3, _len_msg3);
	CHECK_UNIQUE_POINTER(_tmp_dh_session, _len_dh_session);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_uid != NULL && _len_uid != 0) {
		_in_uid = (char*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_uid[_len_uid - 1] = '\0';
		if (_len_uid != strlen(_in_uid) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_msg3 != NULL && _len_msg3 != 0) {
		_in_msg3 = (sgx_dh_msg3_t*)malloc(_len_msg3);
		if (_in_msg3 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s((void*)_in_msg3, _len_msg3, _tmp_msg3, _len_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dh_session != NULL && _len_dh_session != 0) {
		_in_dh_session = (sgx_dh_session_t*)malloc(_len_dh_session);
		if (_in_dh_session == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dh_session, _len_dh_session, _tmp_dh_session, _len_dh_session)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ((_in_ret = (sgx_status_t*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_initiator_proc_msg3(_in_uid, (const sgx_dh_msg3_t*)_in_msg3, _in_dh_session, _in_ret);
err:
	if (_in_uid) free(_in_uid);
	if (_in_msg3) free((void*)_in_msg3);
	if (_in_dh_session) free(_in_dh_session);
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_close_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_close_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_close_session_t* ms = SGX_CAST(ms_ecall_close_session_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_uid = ms->ms_uid;
	size_t _len_uid = ms->ms_uid_len ;
	char* _in_uid = NULL;

	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_uid != NULL && _len_uid != 0) {
		_in_uid = (char*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_uid[_len_uid - 1] = '\0';
		if (_len_uid != strlen(_in_uid) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ecall_close_session(_in_uid);
err:
	if (_in_uid) free(_in_uid);

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_encrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_encrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_encrypt_t* ms = SGX_CAST(ms_ecall_encrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_uid = ms->ms_uid;
	size_t _len_uid = ms->ms_uid_len ;
	char* _in_uid = NULL;
	uint8_t* _tmp_message = ms->ms_message;
	sgx_aes_gcm_data_t* _tmp_response = ms->ms_response;
	sgx_status_t* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(sgx_status_t);
	sgx_status_t* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_uid != NULL && _len_uid != 0) {
		_in_uid = (char*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_uid[_len_uid - 1] = '\0';
		if (_len_uid != strlen(_in_uid) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ((_in_ret = (sgx_status_t*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_encrypt(_in_uid, _tmp_message, ms->ms_message_size, _tmp_response, ms->ms_response_size, _in_ret);
err:
	if (_in_uid) free(_in_uid);
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ret);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_decrypt_t* ms = SGX_CAST(ms_ecall_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_uid = ms->ms_uid;
	size_t _len_uid = ms->ms_uid_len ;
	char* _in_uid = NULL;
	sgx_aes_gcm_data_t* _tmp_message = ms->ms_message;
	uint8_t* _tmp_response = ms->ms_response;
	sgx_status_t* _tmp_ret = ms->ms_ret;
	size_t _len_ret = sizeof(sgx_status_t);
	sgx_status_t* _in_ret = NULL;

	CHECK_UNIQUE_POINTER(_tmp_uid, _len_uid);
	CHECK_UNIQUE_POINTER(_tmp_ret, _len_ret);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_uid != NULL && _len_uid != 0) {
		_in_uid = (char*)malloc(_len_uid);
		if (_in_uid == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_uid, _len_uid, _tmp_uid, _len_uid)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_uid[_len_uid - 1] = '\0';
		if (_len_uid != strlen(_in_uid) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_ret != NULL && _len_ret != 0) {
		if ((_in_ret = (sgx_status_t*)malloc(_len_ret)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_ret, 0, _len_ret);
	}

	ecall_decrypt(_in_uid, _tmp_message, ms->ms_message_size, _tmp_response, ms->ms_response_size, _in_ret);
err:
	if (_in_uid) free(_in_uid);
	if (_in_ret) {
		if (memcpy_s(_tmp_ret, _len_ret, _in_ret, _len_ret)) {
			status = SGX_ERROR_UNEXPECTED;
		}
		free(_in_ret);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_session_request, 0},
		{(void*)(uintptr_t)sgx_ecall_exchange_report, 0},
		{(void*)(uintptr_t)sgx_ecall_init_session, 0},
		{(void*)(uintptr_t)sgx_ecall_initiator_proc_msg1, 0},
		{(void*)(uintptr_t)sgx_ecall_initiator_proc_msg3, 0},
		{(void*)(uintptr_t)sgx_ecall_close_session, 0},
		{(void*)(uintptr_t)sgx_ecall_encrypt, 0},
		{(void*)(uintptr_t)sgx_ecall_decrypt, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


