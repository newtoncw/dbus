/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/*
 * Copyright 2002-2009 Red Hat, Inc.
 * Copyright 2011-2018 Collabora Ltd.
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>

#include "dbus/dbus-internals.h"
#include "dbus/dbus-test.h"
#include "test/test-utils.h"

#include "misc-internals.h"

static DBusTestCase tests[] =
{
  { "string", _dbus_string_test },
  { "sysdeps", _dbus_sysdeps_test },
  { "data-slot", _dbus_data_slot_test },
  { "misc", _dbus_misc_test },
  { "address", _dbus_address_test },
  { "server", _dbus_server_test },
  { "object-tree", _dbus_object_tree_test },
  { "signature", _dbus_signature_test },
  { "marshalling", _dbus_marshal_test },
  { "byteswap", _dbus_marshal_byteswap_test },
  { "memory", _dbus_memory_test },
  { "mem-pool", _dbus_mem_pool_test },
  { "list", _dbus_list_test },
  { "marshal-validate", _dbus_marshal_validate_test },
  { "credentials", _dbus_credentials_test },
  { "keyring", _dbus_keyring_test },
  { "sha", _dbus_sha_test },
  { "auth", _dbus_auth_test },

#if defined(DBUS_UNIX)
  { "userdb", _dbus_userdb_test },
  { "transport-unix", _dbus_transport_unix_test },
#endif

  { NULL }
};

int
main (int    argc,
      char **argv)
{
  return _dbus_test_main (argc, argv, _DBUS_N_ELEMENTS (tests), tests,
                          DBUS_TEST_FLAGS_CHECK_MEMORY_LEAKS,
                          NULL, NULL);
}
