#if !defined (DBUS_INSIDE_DBUS_H) && !defined (DBUS_COMPILATION)
#error "Only <dbus/dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef DBUS_ENCLAVE_SHARED_H
#define DBUS_ENCLAVE_SHARED_H

#include "sgx_eid.h"

const char* _dbus_enclave_shared_error_translate(sgx_status_t status);

sgx_status_t _dbus_enclave_internal_encrypt_message(uint64_t eid, char *uid, uint8_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size);

sgx_status_t _dbus_enclave_internal_decrypt_message(uint64_t eid, char *uid, sgx_aes_gcm_data_t* message, size_t message_size, uint8_t* response, size_t response_size);

void _dbus_enclave_sharec_encrypt_message(DBusTrustedSession *session, DBusMessage *message, DBusError *error);

void _dbus_enclave_shared_decrypt_message(DBusTrustedSession *session, DBusMessage *message, DBusError *error);

#endif /* DBUS_ENCLAVE_SHARED_H */
