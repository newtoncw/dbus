#include "dbus-trusted-session.h"

typedef struct {
	char tdbus_uid[255];
	struct DBusConnection* connection;
	char* destination;
	char* path;
	char* iface;
} DBusTrustedSession;

unsigned long int _dbus_trusted_connection_get_enclave_id (DBusTrustedSession *session) {
	return _dbus_connection_get_enclave_id(session->connection);
}

char* _dbus_trusted_connection_get_session_id (DBusTrustedSession *session) {
	return session->tdbus_uid;
}

DBusTrustedSession* dbus_trusted_connection_create_session (DBusTrustedConnection *connection, const char *destination, const char *path, const char *iface, char *uid) {
	DBusTrustedSession* tdbus_session = malloc(sizeof(DBusTrustedSession));

	tdbus_session->tdbus_connection = connection;

	tdbus_session->destination = malloc(strlen(destination) + 2);
	tdbus_session->path = malloc(strlen(path) + 2);
	tdbus_session->iface = malloc(strlen(iface) + 2);

	strncpy(tdbus_session->destination, destination, strlen(destination));
	strncpy(tdbus_session->path, path, strlen(path));
	strncpy(tdbus_session->iface, iface, strlen(iface));
	strncpy(tdbus_session->tdbus_uid, uid, strlen(uid));

	tdbus_session->destination[strlen(destination)] = '\0';
	tdbus_session->path[strlen(path)] = '\0';
	tdbus_session->iface[strlen(iface)] = '\0';
	tdbus_session->tdbus_uid[strlen(uid)] = '\0';
}
