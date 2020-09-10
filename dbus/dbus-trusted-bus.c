#include <config.h>
#include "dbus-trusted-bus.h"
#include "dbus-bus.h"
#include "dbus-protocol.h"
#include "dbus-internals.h"
#include "dbus-message.h"
#include "dbus-marshal-validate.h"
#include "dbus-misc.h"
#include "dbus-threads-internal.h"
#include "dbus-connection-internal.h"
#include "dbus-string.h"
#include "dbus-enclave-shared.h"
#include "dbus-enclave.h"
#include "dbus-trusted-connection.h"

int dbus_bus_request_trusted_name (DBusTrustedConnection *connection, const char *name, unsigned int flags, DBusError *error) {
	return dbus_bus_request_name(connection, name, flags, error);
}

DBusTrustedConnection* dbus_bus_get_trusted (DBusBusType type, DBusError *error) {
	DBusConnection* conn;
	sgx_enclave_id_t eid;

	conn = dbus_bus_get(type, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	sgx_status_t ret = _dbus_enclave_create_enclave(&eid);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(ret));
		return NULL;
	}

	_dbus_connection_set_enclave_id(conn, eid);

	return conn;
}

DBusTrustedSession* dbus_bus_create_trusted_session (DBusTrustedConnection *connection, const char *destination, const char *path, const char *iface, DBusError *error) {
	sgx_status_t status = SGX_SUCCESS, ret = SGX_SUCCESS;
	sgx_dh_msg1_t dh_msg1;
	sgx_dh_msg2_t dh_msg2;
	sgx_dh_msg3_t dh_msg3;
	sgx_dh_session_t sgx_dh_session;
	char uid[255];

	ret = _dbus_enclave_init_session(_dbus_connection_get_enclave_id(connection), &sgx_dh_session);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(ret));
		return NULL;
	}

	_dbus_enclave_session_request(connection, destination, path, iface, uid, &dh_msg1, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	DBusTrustedSession* session = dbus_trusted_connection_create_session (connection, destination, path, iface, uid);

	ret = _dbus_enclave_initiator_proc_msg1(_dbus_connection_get_enclave_id(connection), uid, &dh_msg1, &dh_msg2, &sgx_dh_session);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(ret));
		return NULL;
	}

	_dbus_enclave_exchange_report(connection, destination, path, iface, &dh_msg2, &dh_msg3, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	ret = _dbus_enclave_initiator_proc_msg3(_dbus_connection_get_enclave_id(connection), uid, &dh_msg3, &sgx_dh_session);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(ret));
		return NULL;
	}

	return session;
}

void dbus_bus_close_trusted_session (DBusTrustedSession *session, DBusError *error) {
	if(!_dbus_enclave_validate_session(session, error)) {
		return;
	}

	sgx_status_t ret = _dbus_enclave_shared_close_session(_dbus_trusted_connection_get_enclave_id(session), _dbus_trusted_connection_get_session_id(session));

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_shared_error_translate(ret));
		return;
	}

	_dbus_enclave_bus_close_session(session, error);
}
