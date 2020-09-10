#include "config.h"
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "sgx_tseal.h"
#include "dbus-errors.h"
#include "dbus-message.h"
#include "dbus-connection.h"
#include "dbus-enclave_u.h"
#include "dbus-string.h"
#define DBUS_CAN_USE_DBUS_STRING_PRIVATE 1
#include "dbus-string-private.h"
#include <stddef.h>

sgx_status_t _dbus_enclave_shared_close_session(uint64_t eid, char *uid) {
	return ecall_close_session(eid, uid);
}
