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
#include "dbus-trusted-session.h"

DBUS_BEGIN_DECLS

typedef struct DBusConnection DBusTrustedConnection;

DBUS_EXPORT
dbus_bool_t        dbus_trusted_connection_send                 (DBusTrustedSession         *session,
                                                                 DBusMessage                *message,
                                                                 dbus_uint32_t              *client_serial);
DBUS_EXPORT
DBusMessage* 	   dbus_trusted_connection_send_with_reply_and_block (DBusTrustedSession    *session, 
								 DBusMessage 		    *message, 
								 int 			     timeout_milliseconds, 
								 DBusError 		    *error);
DBUS_EXPORT
void 		   dbus_trusted_connection_send_preallocated   (DBusTrustedSession 	    *session, 
							 	DBusPreallocatedSend 	    *preallocated, 
								DBusMessage 		    *message, 
								dbus_uint32_t 		    *client_serial);
DBUS_EXPORT
dbus_bool_t 	   dbus_trusted_connection_send_with_reply     (DBusTrustedSession 	    *session, 
								DBusMessage 		    *message, 
								DBusPendingCall 	   **pending_return, 
								int 			     timeout_milliseconds);

DBUS_END_DECLS

#endif /* DBUS_TRUSTED_CONNECTION_H */
