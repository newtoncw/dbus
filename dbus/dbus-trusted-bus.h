#if !defined (DBUS_INSIDE_DBUS_H) && !defined (DBUS_COMPILATION)
#error "Only <dbus/dbus.h> can be included directly, this file may disappear or change contents."
#endif

#ifndef DBUS_TRUSTED_BUS_H
#define DBUS_TRUSTED_BUS_H

#include <dbus/dbus-connection.h>
#include <dbus/dbus-trusted-connection.h>

DBUS_BEGIN_DECLS

DBUS_EXPORT
DBusTrustedConnection *dbus_bus_get_trusted (DBusBusType   type,
					   DBusError      *error);
DBUS_EXPORT
int
dbus_bus_request_trusted_name             (DBusTrustedConnection *connection,
                                           const char     *name,
                                           unsigned int    flags,
                                           DBusError      *error);
DBUS_EXPORT
DBusTrustedSession* 
dbus_bus_create_trusted_session 	  (DBusTrustedConnection *connection, 
					   const char 	  *destination, 
					   const char     *path, 
					   const char     *iface, 
					   DBusError      *error);
DBUS_EXPORT
void 
dbus_bus_close_trusted_session 		  (DBusTrustedSession *session, 
					   DBusError      *error);

DBUS_END_DECLS

#endif /* DBUS_TRUSTED_BUS_H */
