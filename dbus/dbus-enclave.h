#if !defined (DBUS_INSIDE_DBUS_H) && !defined (DBUS_COMPILATION)
#error "Only <dbus/dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef DBUS_ENCLAVE_H
#define DBUS_ENCLAVE_H

#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_dh.h"

dbus_bool_t _dbus_enclave_validate_session(DBusTrustedSession *session, DBusError *error);

sgx_status_t _dbus_enclave_create_enclave(sgx_enclave_id_t* tdbus_eid);

void _dbus_enclave_session_request(DBusTrustedConnection *connection, const char *destination, const char *path, const char *iface, char *uid, sgx_dh_msg1_t *dh_msg1, DBusError *error);

void _dbus_enclave_exchange_report(DBusTrustedConnection *connection, const char *destination, const char *path, const char *iface, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, DBusError *error);

void _dbus_enclave_bus_close_session(DBusTrustedSession *session, DBusError *error);

sgx_status_t _dbus_enclave_init_session(uint64_t eid, sgx_dh_session_t *session);

sgx_status_t _dbus_enclave_initiator_proc_msg1(uint64_t eid, char *uid, const sgx_dh_msg1_t *msg1, sgx_dh_msg2_t *msg2, sgx_dh_session_t *dh_session);

sgx_status_t _dbus_enclave_initiator_proc_msg3(uint64_t eid, char *uid, const sgx_dh_msg3_t *msg3, sgx_dh_session_t *dh_session);

#endif /* DBUS_ENCLAVE_H */
