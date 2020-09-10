#if !defined (DBUS_INSIDE_DBUS_H) && !defined (DBUS_COMPILATION)
#error "Only <dbus/dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef DBUS_TRUSTED_SESSION_H
#define DBUS_TRUSTED_SESSION_H

#include <dbus/dbus-errors.h>
#include <dbus/dbus-macros.h>
#include <dbus/dbus-memory.h>
#include <dbus/dbus-message.h>
#include <dbus/dbus-shared.h>
#include "dbus-trusted-connection.h"

DBUS_BEGIN_DECLS

typedef struct DBusTrustedSession DBusTrustedSession;

DBusTrustedSession* dbus_trusted_connection_create_session (DBusTrustedConnection *connection, const char *destination, const char *path, const char *iface, char *uid);
unsigned long int _dbus_trusted_connection_get_enclave_id              (DBusTrustedSession     *session);
char* _dbus_trusted_connection_get_session_id              (DBusTrustedSession     *session);

DBUS_END_DECLS

#endif /* DBUS_TRUSTED_SESSION_H */
