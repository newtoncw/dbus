#include <config.h>
#include "dbus-shared.h"
#include "dbus-trusted-connection.h"
#include "dbus-connection.h"
#include "dbus-pending-call.h"
#include "dbus-message.h"
#include "dbus-enclave-shared.h"

dbus_bool_t dbus_trusted_connection_send (DBusTrustedSession *session, DBusMessage *message, dbus_uint32_t *serial, DBusError *error) {
	if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		_dbus_enclave_sharec_encrypt_message(session, message, error);
	}

	return dbus_connection_send(session->connection, message, serial);
}

DBusMessage* dbus_trusted_connection_send_with_reply_and_block (DBusTrustedSession *session, DBusMessage *message, int timeout_milliseconds, DBusError *error) {
	if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		_dbus_enclave_sharec_encrypt_message(session, message, error);
	}

	return dbus_connection_send_with_reply_and_block(session->connection, message, timeout_milliseconds, error);
}

void dbus_trusted_connection_send_preallocated (DBusTrustedSession *session, DBusPreallocatedSend *preallocated, DBusMessage *message, dbus_uint32_t *client_serial) {
	if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		_dbus_enclave_sharec_encrypt_message(session, message, error);
	}

	dbus_connection_send_preallocated(session->connection, preallocated, message, client_serial);
}

dbus_bool_t dbus_trusted_connection_send_with_reply (DBusTrustedSession *session, DBusMessage *message, DBusPendingCall **pending_return, int timeout_milliseconds) {
	if(dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_METHOD_CALL) {
		_dbus_enclave_sharec_encrypt_message(session, message, error);
	}

	return dbus_connection_send_with_reply(session->connection, message, pending_return, timeout_milliseconds);
}
