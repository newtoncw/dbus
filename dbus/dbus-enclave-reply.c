#include "sgx_eid.h"
#include "sgx_urts.h"
#include "dbus-enclave_u.h"
#include "dbus-enclave-shared.h"

sgx_status_t _dbus_enclave_reply_session_request(uint64_t eid, char *uid, sgx_dh_msg1_t *dh_msg1) {
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	status = ecall_session_request(eid, uid, dh_msg1, &status2);

	if(status != SGX_SUCCESS) {
		return status;
	} else {
		return status2;
	}
}

sgx_status_t _dbus_enclave_reply_exchange_report(uint64_t eid, char *uid, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3) {
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	status = ecall_exchange_report(eid, uid, dh_msg2, dh_msg3, &status2);

	if(status != SGX_SUCCESS) {
		return status;
	} else {
		return status2;
	}
}

void _dbus_enclave_reply_close_session(uint64_t eid, char *uid) {
	return ecall_close_session(eid, uid);
}
