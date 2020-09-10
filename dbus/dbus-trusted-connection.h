#if !defined (DBUS_INSIDE_DBUS_H) && !defined (DBUS_COMPILATION)
#error "Only <dbus/dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef DBUS_TRUSTED_CONNECTION_H
#define DBUS_TRUSTED_CONNECTION_H

#include <dbus/dbus-errors.h>
#include <dbus/dbus-macros.h>
#include <dbus/dbus-memory.h>
#include <dbus/dbus-message.h>
#include <dbus/dbus-shared.h>

DBUS_BEGIN_DECLS

typedef struct DBusConnection DBusTrustedConnection;

typedef struct DBusTrustedSession DBusTrustedSession;

DBUS_EXPORT
dbus_bool_t        dbus_trusted_connection_send                 (DBusTrustedSession         *session,
                                                                 DBusMessage                *message,
                                                                 dbus_uint32_t              *client_serial);

DBUS_END_DECLS

#endif /* DBUS_TRUSTED_CONNECTION_H */
