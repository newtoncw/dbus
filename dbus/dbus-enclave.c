#include "sgx_eid.h"
#include "sgx_urts.h"
#include "dbus-enclave_u.h"
#include "dbus-message.h"
#include "dbus-string.h"
#include "dbus-string-private.h"
#include "dbus-shared.h"
#include "dbus-enclave-shared.h"

#define ENCLAVE_FILENAME "dbus_enclave.signed.so"

dbus_bool_t _dbus_enclave_validate_session(TDBusSession *session, DBusError *error) {
	if(session == NULL) {
		dbus_set_error_const(error, "Session ERROR", "Session must be not null");
		return FALSE;
	} else if(session->connection == NULL) {
		dbus_set_error_const(error, "Session ERROR", "Connection must be not null");
		return FALSE;
	} else if(strlen(session->tdbus_uid) == 0) {
		dbus_set_error_const(error, "Session ERROR", "Invalid session id");
		return FALSE;
	}

	return TRUE;
}

sgx_status_t _dbus_enclave_create_enclave(sgx_enclave_id_t* tdbus_eid) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	sgx_launch_token_t token = {0};

	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, tdbus_eid, NULL);

	return ret;
}

void _dbus_enclave_session_request(TDBusConnection *connection, const char *destination, const char *path, const char *iface, char *uid, sgx_dh_msg1_t *dh_msg1, DBusError *error) {
	sgx_status_t ret = SGX_SUCCESS;
	DBusMessage* reply;
	DBusMessage* msg;
	char *pReadData;
	int len;

	msg = dbus_message_new_method_call(destination, path, iface, DBUS_TRUSTED_SESSION_REQUEST);
	if (msg == NULL) {
		dbus_set_error_const(error, "NULL message", "dbus_message_new_method_call failed");
		return;
	}

	//dbus_message_append_args(msg, DBUS_TYPE_UINT64, &(connection->tdbus_uid), DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, DBUS_TIMEOUT_USE_DEFAULT, error);

	dbus_message_unref(msg);

	if (dbus_error_is_set(error)) {
		return;
	}

	if(reply == NULL) {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	if (!dbus_message_get_args(reply, error, DBUS_TYPE_UINT32, &ret, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pReadData, &len, DBUS_TYPE_INVALID)) {
		return;
	}
	strncpy(uid, dbus_message_get_sender(reply), strlen(dbus_message_get_sender(reply)));

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(ret));
		return;
	}

	if (len > 0) {
		memcpy(dh_msg1, pReadData, len);
	} else {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	dbus_message_unref(reply);
}

void _dbus_enclave_exchange_report(TDBusConnection *connection, const char *destination, const char *path, const char *iface, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, DBusError *error) {
	sgx_status_t ret = SGX_SUCCESS;
	DBusMessage* reply;
	DBusMessage* msg;
	char *p_read_dh_msg3;
	int len_dh_msg3;

	msg = dbus_message_new_method_call(destination, path, iface, DBUS_TRUSTED_EXCHANGE_REPORT);
	if (msg == NULL) {
		dbus_set_error_const(error, "NULL message", "dbus_message_new_method_call failed");
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dh_msg2, sizeof(sgx_dh_msg2_t), DBUS_TYPE_INVALID);

	reply = dbus_connection_send_with_reply_and_block(connection, msg, DBUS_TIMEOUT_USE_DEFAULT, error);

	dbus_message_unref(msg);

	if (dbus_error_is_set(error)) {
		return;
	}

	if(reply == NULL) {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	if (!dbus_message_get_args(reply, error, DBUS_TYPE_UINT32, &ret, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &p_read_dh_msg3, &len_dh_msg3, DBUS_TYPE_INVALID)) {
		return;
	}

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(ret));
		return;
	}

	if (len_dh_msg3 > 0) {
		memcpy(dh_msg3, p_read_dh_msg3, len_dh_msg3);
	} else {
		dbus_set_error_const(error, "NULL reply", "Server sent null reply");
		return;
	}

	dbus_message_unref(reply);
}

void _dbus_enclave_bus_close_session(TDBusSession *session, DBusError *error) {
	sgx_status_t ret = SGX_SUCCESS;
	DBusMessage* reply;
	DBusMessage* msg;
	char *p_read_dh_msg3;
	int len_dh_msg3;

	msg = dbus_message_new_method_call(session->destination, session->path, session->iface, DBUS_TRUSTED_CLOSE_SESSION);
	if (msg == NULL) {
		return;
	}

	dbus_message_append_args(msg, DBUS_TYPE_UINT64, &(session->tdbus_connection->tdbus_uid), DBUS_TYPE_INVALID);

	dbus_connection_send(session->connection, msg, NULL);
}

sgx_status_t _dbus_enclave_init_session(uint64_t eid, sgx_dh_session_t *session) {
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	status2 = ecall_init_session(eid, session, &status);

	if(status != SGX_SUCCESS) {
		return status;
	} else {
		return status2;
	}
}

sgx_status_t _dbus_enclave_initiator_proc_msg1(uint64_t eid, char *uid, const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_dh_session_t *dh_session) {
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	status2 = ecall_initiator_proc_msg1(eid, uid, msg1, msg2, dh_session, &status);

	if(status != SGX_SUCCESS) {
		return status;
	} else {
		return status2;
	}
}

sgx_status_t _dbus_enclave_initiator_proc_msg3(uint64_t eid, char *uid, const sgx_dh_msg3_t *msg3, sgx_dh_session_t *dh_session) {
	sgx_status_t status = SGX_SUCCESS, status2 = SGX_SUCCESS;
	status2 = ecall_initiator_proc_msg3(eid, uid, msg3, dh_session, &status);

	if(status != SGX_SUCCESS) {
		return status;
	} else {
		return status2;
	}
}
