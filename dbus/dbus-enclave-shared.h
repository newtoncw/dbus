#if !defined (DBUS_INSIDE_DBUS_H) && !defined (DBUS_COMPILATION)
#error "Only <dbus/dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef DBUS_ENCLAVE_SHARED_H
#define DBUS_ENCLAVE_SHARED_H

#include "sgx_eid.h"
#include "sgx_error.h"
#include "sgx_dh.h"
#include "sgx_tseal.h"
#include "dbus-connection.h"

sgx_status_t _dbus_enclave_shared_close_session(uint64_t eid, char *uid);

#endif /* DBUS_ENCLAVE_SHARED_H */
