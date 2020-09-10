#include <config.h>
#include "dbus-trusted-bus.h"
#include "dbus-protocol.h"
#include "dbus-internals.h"
#include "dbus-message.h"
#include "dbus-marshal-validate.h"
#include "dbus-misc.h"
#include "dbus-threads-internal.h"
#include "dbus-connection-internal.h"
#include "dbus-string.h"
#include "dbus-enclave.h"

int dbus_bus_request_trusted_name (DBusTrustedConnection *connection, const char *name, unsigned int flags, DBusError *error) {
	return dbus_bus_request_name(connection->tdbus_connection, name, flags, error);
}

DBusTrustedConnection* dbus_bus_get_trusted (DBusBusType type, DBusError *error) {
	TDBusConnection* conn;

	conn = dbus_bus_get(type, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	sgx_status_t ret = _dbus_enclave_create_enclave(&eid);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_error_translate(ret));
		return NULL;
	}

	conn->enclave_id = eid;

	return conn;
}

TDBusSession* dbus_bus_create_trusted_session (TDBusConnection *connection, const char *destination, const char *path, const char *iface, DBusError *error) {
	sgx_status_t status = SGX_SUCCESS, ret = SGX_SUCCESS;
	sgx_dh_msg1_t dh_msg1;
	sgx_dh_msg2_t dh_msg2;
	sgx_dh_msg3_t dh_msg3;
	sgx_dh_session_t sgx_dh_session;
	char uid[255];
	TDBusSession* tdbus_session = malloc(sizeof(TDBusSession));

	tdbus_session->tdbus_connection = connection;

	tdbus_session->destination = malloc(strlen(destination) + 2);
	tdbus_session->path = malloc(strlen(path) + 2);
	tdbus_session->iface = malloc(strlen(iface) + 2);

	strncpy(tdbus_session->destination, destination, strlen(destination));
	strncpy(tdbus_session->path, path, strlen(path));
	strncpy(tdbus_session->iface, iface, strlen(iface));

	tdbus_session->destination[strlen(destination)] = '\0';
	tdbus_session->path[strlen(path)] = '\0';
	tdbus_session->iface[strlen(iface)] = '\0';

	ret = _dbus_enclave_init_session(connection->enclave_id, &sgx_dh_session);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_error_translate(ret));
		return NULL;
	}

	_dbus_enclave_session_request(connection, destination, path, iface, uid, &dh_msg1, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	strncpy(tdbus_session->tdbus_uid, uid, strlen(uid));
	tdbus_session->tdbus_uid[strlen(uid)] = '\0';

	ret = _dbus_enclave_initiator_proc_msg1(connection->enclave_id, uid, &dh_msg1, &dh_msg2, &sgx_dh_session);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_error_translate(ret));
		return NULL;
	}

	_dbus_enclave_exchange_report(connection, destination, path, iface, &dh_msg2, &dh_msg3, error);

	if (dbus_error_is_set(error)) {
		return NULL;
	}

	ret = _dbus_enclave_initiator_proc_msg3(connection->enclave_id, uid, &dh_msg3, &sgx_dh_session);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_error_translate(ret));
		return NULL;
	}

	return tdbus_session;
}

void dbus_bus_close_trusted_session (TDBusSession *session, DBusError *error) {
	if(!_dbus_enclave_validate_session(session, error)) {
		return;
	}

	sgx_status_t ret = _dbus_enclave_reply_close_session(session->tdbus_connection->tdbus_eid, session->tdbus_uid);

	if(ret != SGX_SUCCESS) {
		dbus_set_error_const(error, "SGX ERROR", _dbus_enclave_error_translate(ret));
		return;
	}

	_dbus_enclave_bus_close_session(session, error);
}
