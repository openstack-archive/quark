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
from quantum.db import api as db_api

from quark.db import models
import quark.drivers.nvp_driver
from quark.tests import test_base


class TestNVPDriver(test_base.TestBase):
    def setUp(self):
        super(TestNVPDriver, self).setUp()

        if not hasattr(self, 'driver'):
            self.driver = quark.drivers.nvp_driver.NVPDriver()

        cfg.CONF.set_override('sql_connection', 'sqlite://', 'DATABASE')
        self.driver.max_ports_per_switch = 0
        db_api.configure_db()
        models.BASEV2.metadata.create_all(db_api._ENGINE)

        self.lswitch_uuid = "12345678-1234-1234-1234-123456781234"
        self.context.tenant_id = "tid"
        self.lport_uuid = "12345678-0000-0000-0000-123456781234"
        self.net_id = "12345678-1234-1234-1234-123412341234"
        self.port_id = "12345678-0000-0000-0000-123412341234"
        self.d_pkg = "quark.drivers.nvp_driver.NVPDriver"
        self.max_spanning = 3

    def _create_connection(self, switch_count=1,
                           has_switches=False, maxed_ports=False):
        connection = mock.Mock()
        lswitch = self._create_lswitch(has_switches, maxed_ports=maxed_ports)
        lswitchport = self._create_lswitch_port(self.lswitch_uuid,
                                                switch_count)
        connection.lswitch_port = mock.Mock(return_value=lswitchport)
        connection.lswitch = mock.Mock(return_value=lswitch)
        return connection

    def _create_lswitch_port(self, switch_uuid, switch_count):
        port = mock.Mock()
        port.create = mock.Mock(return_value={'uuid': self.lport_uuid})
        port_query = self._create_lport_query(switch_count)
        port.query = mock.Mock(return_value=port_query)
        port.delete = mock.Mock(return_value=None)
        return port

    def _create_lport_query(self, switch_count):
        query = mock.Mock()
        port_list = {"_relations":
                    {"LogicalSwitchConfig":
                    {"uuid": self.lswitch_uuid}}}
        port_query = {"results": [port_list], "result_count": switch_count}
        query.results = mock.Mock(return_value=port_query)
        return query

    def _create_lswitch(self, switches_available, maxed_ports):
        lswitch = mock.Mock()
        lswitch.query = mock.Mock(
            return_value=self.
            _create_lswitch_query(switches_available, maxed_ports))
        lswitch.create = mock.Mock(return_value={'uuid': self.lswitch_uuid})
        lswitch.delete = mock.Mock(return_value=None)
        return lswitch

    def _create_lswitch_query(self, switches_available, maxed_ports):
        query = mock.Mock()
        port_count = 0
        if maxed_ports:
            port_count = self.max_spanning
        lswitch_list = [{'uuid': 'abcd',
                        '_relations': {
                        'LogicalSwitchStatus': {
                        'lport_count': port_count
                        }}}]
        if not switches_available:
            lswitch_list = []
        lswitch_query = {"results": lswitch_list}
        query.relations = mock.Mock(return_value=None)
        query.results = mock.Mock(return_value=lswitch_query)
        return query

    def tearDown(self):
        db_api.clear_db()


class TestNVPDriverCreateNetwork(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("%s.get_connection" % self.d_pkg),
        ) as (get_connection,):
            connection = self._create_connection()
            get_connection.return_value = connection
            yield connection

    def test_create_network(self):
        with self._stubs() as (connection):
            self.driver.create_network(self.context, "test")
            self.assertTrue(connection.lswitch().create.called)


class TestNVPDriverDeleteNetwork(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, network_exists=True):
        with contextlib.nested(
            mock.patch("%s.get_connection" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (get_connection, switch_list):
            connection = self._create_connection()
            get_connection.return_value = connection
            if network_exists:
                ret = {"results": [{"uuid": self.lswitch_uuid}]}
            else:
                ret = {"results": []}
            switch_list().results = mock.Mock(return_value=ret)
            yield connection

    def test_delete_network(self):
        with self._stubs() as (connection):
            self.driver.delete_network(self.context, "test")
            self.assertTrue(connection.lswitch().delete.called)

    def test_delete_network_not_exists(self):
        with self._stubs(network_exists=False) as (connection):
            self.driver.delete_network(self.context, "test")
            self.assertFalse(connection.lswitch().delete.called)


class TestNVPDriverCreatePort(TestNVPDriver):
    '''In all cases an lswitch should be queried.'''
    @contextlib.contextmanager
    def _stubs(self, has_lswitch=True, maxed_ports=False):
        with contextlib.nested(
            mock.patch("%s.get_connection" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (get_connection, get_switches):
            connection = self._create_connection(has_switches=has_lswitch,
                                                 maxed_ports=maxed_ports)
            get_connection.return_value = connection
            get_switches.return_value = connection.lswitch().query()
            yield connection

    def test_create_port_switch_exists(self):
        with self._stubs() as (connection):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
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
            self.assertTrue(connection.lswitch().query.called)
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
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(False in status_args)

    def test_create_port_switch_exists_spanning(self):
        with self._stubs(maxed_ports=True) as (connection):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_port_switch_not_exists_spanning(self):
        with self._stubs(has_lswitch=False, maxed_ports=True) as (connection):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_disabled_port_switch_not_exists_spanning(self):
        with self._stubs(has_lswitch=False, maxed_ports=True) as (connection):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id, False)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(False in status_args)


class TestNVPDriverDeletePort(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, single_switch=True):
        with contextlib.nested(
            mock.patch("%s.get_connection" % self.d_pkg),
        ) as (get_connection,):
            if not single_switch:
                connection = self._create_connection(switch_count=2)
            else:
                connection = self._create_connection(switch_count=1)
            get_connection.return_value = connection
            yield connection

    def test_delete_port(self):
        with self._stubs() as (connection):
            self.driver.delete_port(self.context, self.port_id)
            self.assertTrue(connection.lswitch_port().delete.called)

    def test_delete_port_switch_given(self):
        with self._stubs() as (connection):
            self.driver.delete_port(self.context, self.port_id,
                                    self.lswitch_uuid)
            self.assertFalse(connection.lswitch_port().query.called)
            self.assertTrue(connection.lswitch_port().delete.called)

    def test_delete_port_many_switches(self):
        with self._stubs(single_switch=False):
            with self.assertRaises(Exception):
                self.driver.delete_port(self.context, self.port_id)
