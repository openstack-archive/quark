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

from sqlalchemy.dialects import mysql, sqlite

from quark.db import custom_types
from quark.tests import test_base


class TestDBCustomTypesINET(test_base.TestBase):
    """Adding for coverage of the custom types."""

    def setUp(self):
        super(TestDBCustomTypesINET, self).setUp()
        self.inet = custom_types.INET()

    def test_inet_load_dialect_impl(self):
        dialect = self.inet.load_dialect_impl(mysql.dialect())
        self.assertEqual(type(dialect), type(custom_types.INET.impl()))

    def test_inet_load_dialect_impl_sqlite(self):
        dialect = self.inet.load_dialect_impl(sqlite.dialect())
        self.assertEqual(type(dialect), sqlite.CHAR)

    def test_process_bind_param(self):
        bind = self.inet.process_bind_param(None, None)
        self.assertIsNone(bind)

    def test_process_bind_param_with_value(self):
        bind = self.inet.process_bind_param("foo", sqlite.dialect())
        self.assertEqual(bind, "foo")

    def test_process_bind_param_with_value_not_sqlite(self):
        bind = self.inet.process_bind_param("foo", mysql.dialect())
        self.assertEqual(bind, "foo")

    def test_process_result_value(self):
        bind = self.inet.process_result_value(None, mysql.dialect())
        self.assertIsNone(bind)

    def test_process_result_value_with_value(self):
        bind = self.inet.process_result_value(1.0, sqlite.dialect())
        self.assertEqual(bind, 1.0)

    def test_process_result_value_with_value_not_sqlite(self):
        bind = self.inet.process_result_value(1.0, mysql.dialect())
        self.assertEqual(bind, 1.0)


class TestDBCustomTypesMACAddress(test_base.TestBase):
    """Adding for coverage of the mac address custom types."""

    def setUp(self):
        super(TestDBCustomTypesMACAddress, self).setUp()
        self.mac = custom_types.MACAddress()

    def test_mac_load_dialect_impl(self):
        dialect = self.mac.load_dialect_impl(sqlite.dialect())
        self.assertEqual(type(dialect), sqlite.CHAR)

    def test_mac_load_dialect_impl_not_sqlite(self):
        dialect = self.mac.load_dialect_impl(mysql.dialect())
        self.assertEqual(type(dialect), type(custom_types.MACAddress.impl()))
