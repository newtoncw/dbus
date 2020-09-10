#if !defined (DBUS_INSIDE_DBUS_H) && !defined (DBUS_COMPILATION)
#error "Only <dbus/dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef DBUS_ENCLAVE_REPLY_H
#define DBUS_ENCLAVE_REPLY_H

#include "sgx_eid.h"

sgx_status_t _dbus_enclave_reply_session_request(uint64_t eid, char *uid, sgx_dh_msg1_t *dh_msg1);

sgx_status_t _dbus_enclave_reply_exchange_report(uint64_t eid, char *uid, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3);

sgx_status_t _dbus_enclave_reply_close_session(uint64_t eid, char *uid);

#endif /* DBUS_ENCLAVE_REPLY_H */
