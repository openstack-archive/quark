# Copyright 2013 Openstack Foundation
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

from oslo.config import cfg
from quantum import context
from quantum.db import api as db_api

import quark.drivers.nvp_driver

import test_base


class TestNVPDriver(test_base.TestBase):
    def setUp(self):
        cfg.CONF.set_override('sql_connection', 'sqlite://', 'DATABASE')
        db_api.configure_db()
        self.context = context.get_admin_context()
        self.driver = quark.drivers.nvp_driver.NVPDriver()
        self.lswitch_uuid = "12345678-1234-1234-1234-123456781234"
        self.lport_uuid = "12345678-0000-0000-0000-123456781234"
        self.net_id = "12345678-1234-1234-1234-123412341234"
        self.port_id = "12345678-0000-0000-0000-123412341234"

    def _create_connection(self):
        connection = mock.Mock()
        lswitch = self._create_lswitch()
        lswitchport = self._create_lswitch_port(self.lswitch_uuid)
        connection.lswitch_port = mock.Mock(return_value=lswitchport)
        connection.lswitch = mock.Mock(return_value=lswitch)
        return connection

    def _create_lswitch_port(self, switch_uuid):
        port = mock.Mock()
        port.create = mock.Mock(return_value={'uuid': self.lport_uuid})
        return port

    def _create_lswitch(self):
        lswitch = mock.Mock()
        lswitch.query = mock.Mock(return_value=self._create_lswitch_query())
        lswitch.create = mock.Mock(return_value={'uuid': self.lswitch_uuid})
        return lswitch

    def _create_lswitch_query(self):
        query = mock.Mock()
        lswitch_list = [{'uuid': 'abcd'}]
        lswitch_query = {"results": lswitch_list}

        query.results = mock.Mock(return_value=lswitch_query)
        return query

    def tearDown(self):
        db_api.clear_db()


class TestNVPDriverCreatePort(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, has_lswitch=True):
        driver = "quark.drivers.nvp_driver.NVPDriver"
        with contextlib.nested(
            mock.patch("%s.get_connection" % driver),
            mock.patch("%s._lswitch_select_open" % driver),
        ) as (get_connection, select_open):
            connection = self._create_connection()
            get_connection.return_value = connection
            if has_lswitch:
                select_open.return_value = self.lswitch_uuid
            else:
                select_open.return_value = None
            yield connection

    def test_create_port_switch_exists(self):
        with self._stubs() as (connection):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_port_switch_not_exists(self):
        with self._stubs(has_lswitch=False) as (connection):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_disabled_port_switch_not_exists(self):
        with self._stubs(has_lswitch=False) as (connection):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id, False)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(False in status_args)
