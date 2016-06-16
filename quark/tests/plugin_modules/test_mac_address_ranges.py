# Copyright 2013 Rackspace Hosting Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
#  under the License.

import contextlib

import mock
import netaddr
from neutron_lib import exceptions as n_exc

from quark.db import api as db_api
from quark import exceptions as q_exc
from quark.plugin_modules import mac_address_ranges
from quark.tests import test_quark_plugin


class TestQuarkGetMacAddressRanges(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        old_context = self.context
        self.context = self.context.elevated()
        with mock.patch("%s.mac_address_range_find" % db_mod) as mar_find:
            mar_find.return_value = mac_range
            yield
        self.context = old_context

    def test_find_mac_ranges(self):
        mar = dict(id=1, cidr="AA:BB:CC/24")
        with self._stubs([mar]):
            res = self.plugin.get_mac_address_ranges(self.context)
            self.assertEqual(res[0]["id"], mar["id"])
            self.assertEqual(res[0]["cidr"], mar["cidr"])

    def test_find_mac_range(self):
        mar = dict(id=1, cidr="AA:BB:CC/24")
        with self._stubs(mar):
            res = self.plugin.get_mac_address_range(self.context, 1)
            self.assertEqual(res["id"], mar["id"])
            self.assertEqual(res["cidr"], mar["cidr"])

    def test_find_mac_range_fail(self):
        with self._stubs(None):
            with self.assertRaises(q_exc.MacAddressRangeNotFound):
                self.plugin.get_mac_address_range(self.context, 1)


class TestQuarkCreateMacAddressRanges(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        old_context = self.context
        self.context = self.context.elevated()
        with mock.patch("%s.mac_address_range_create" % db_mod) as mar_create:
            mar_create.return_value = mac_range
            yield
        self.context = old_context

    def test_create_range(self):
        mar = dict(mac_address_range=dict(id=1, cidr="AA:BB:CC/24"))
        with self._stubs(mar["mac_address_range"]):
            res = self.plugin.create_mac_address_range(self.context, mar)
            self.assertEqual(res["id"], mar["mac_address_range"]["id"])
            self.assertEqual(res["cidr"], mar["mac_address_range"]["cidr"])

    def test_to_mac_range_cidr_format(self):
        cidr, first, last = mac_address_ranges._to_mac_range("AA:BB:CC/24")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_just_prefix(self):
        cidr, first, last = mac_address_ranges._to_mac_range("AA:BB:CC")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_unix_format(self):
        cidr, first, last = mac_address_ranges._to_mac_range("AA-BB-CC")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_unix_cidr_format(self):
        cidr, first, last = mac_address_ranges._to_mac_range("AA-BB-CC/24")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/24")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cd:0:0:0")

    def test_to_mac_range_unix_cidr_format_normal_length(self):
        cidr, first, last = mac_address_ranges._to_mac_range("aabbcc000000/29")
        first_mac = str(netaddr.EUI(first, dialect=netaddr.mac_unix))
        last_mac = str(netaddr.EUI(last, dialect=netaddr.mac_unix))
        self.assertEqual(cidr, "AA:BB:CC:00:00:00/29")
        self.assertEqual(first_mac, "aa:bb:cc:0:0:0")
        self.assertEqual(last_mac, "aa:bb:cc:8:0:0")

    def test_to_mac_prefix_too_short_fails(self):
        with self.assertRaises(q_exc.InvalidMacAddressRange):
            cidr, first, last = mac_address_ranges._to_mac_range("AA-BB")

    def test_to_mac_prefix_too_long_fails(self):
        with self.assertRaises(q_exc.InvalidMacAddressRange):
            cidr, first, last = mac_address_ranges._to_mac_range(
                "AA-BB-CC-DD-EE-F0-00")

    def test_to_mac_prefix_is_garbage_fails(self):
        with self.assertRaises(q_exc.InvalidMacAddressRange):
            cidr, first, last = mac_address_ranges._to_mac_range("F0-0-BAR")

    def test_create_range_with_do_not_use(self):
        mar = dict(mac_address_range=dict(id=1, cidr="AA:BB:CC/24",
                                          do_not_use=True))
        admin_ctxt = self.context.elevated()
        res = self.plugin.create_mac_address_range(admin_ctxt, mar)
        self.assertEqual(res["cidr"], "AA:BB:CC:00:00:00/24")
        mac_range = db_api.mac_address_range_find(admin_ctxt,
                                                  id=res["id"]).first()
        self.assertTrue(mac_range["do_not_use"])


class TestQuarkDeleteMacAddressRanges(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, mac_range):
        db_mod = "quark.db.api"
        old_context = self.context
        self.context = self.context.elevated()
        with contextlib.nested(
            mock.patch("%s.mac_address_range_find" % db_mod),
            mock.patch("%s.mac_address_range_delete" % db_mod),
        ) as (mar_find, mar_delete):
            mar_find.return_value = mac_range
            yield mar_delete
        self.context = old_context

    def test_mac_address_range_delete_not_found(self):
        with self._stubs(None):
            with self.assertRaises(q_exc.MacAddressRangeNotFound):
                self.plugin.delete_mac_address_range(self.context, 1)

    def test_mac_address_range_delete_in_use(self):
        mar = mock.MagicMock()
        mar.id = 1
        mar.allocated_macs = 1
        with self._stubs(mar):
            with self.assertRaises(q_exc.MacAddressRangeInUse):
                self.plugin.delete_mac_address_range(self.context, 1)

    def test_mac_address_range_delete_success(self):
        mar = mock.MagicMock()
        mar.id = 1
        mar.allocated_macs = 0
        with self._stubs(mar) as mar_delete:
            resp = self.plugin.delete_mac_address_range(self.context, 1)
            self.assertIsNone(resp)
            mar_delete.assert_called_once_with(self.context, mar)


class TestQuarkMacAddressCRUDNotAdminRaises(test_quark_plugin.TestQuarkPlugin):
    def test_mac_ranges_index_fails(self):
        with self.assertRaises(n_exc.NotAuthorized):
            self.plugin.get_mac_address_ranges(self.context)

    def test_show_mac_range_fails(self):
        with self.assertRaises(n_exc.NotAuthorized):
            self.plugin.get_mac_address_range(self.context, 1)

    def test_create_mac_range_fails(self):
        with self.assertRaises(n_exc.NotAuthorized):
            self.plugin.create_mac_address_range(
                self.context, {"mac_address_range": 1})

    def test_delete_mac_range_fails(self):
        with self.assertRaises(n_exc.NotAuthorized):
            self.plugin.delete_mac_address_range(self.context, 1)
