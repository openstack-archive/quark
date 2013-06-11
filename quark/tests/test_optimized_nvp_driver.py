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

import quark.drivers.nvp_driver
import quark.tests.test_nvp_driver as test_nvp_driver


class TestOptimizedNVPDriver(test_nvp_driver.TestNVPDriver):
    def setUp(self):
        if not hasattr(self, 'driver'):
            self.driver = quark.drivers.nvp_driver.OptimizedNVPDriver()
        super(TestOptimizedNVPDriver, self).setUp()
        self.d_pkg = "quark.drivers.nvp_driver.OptimizedNVPDriver"
        self.context.session.add = mock.Mock(return_value=None)
        self.net_id = "12345678-1234-0000-1234-123412341234"

    def _create_lswitch_mock(self):
        lswitch = mock.Mock(id=self.lswitch_uuid, port_count=1)
        return lswitch

    def _create_lport_mock(self, port_count):
        lport = mock.Mock()
        lport.id = self.lport_uuid
        lport.switch.id = self.lswitch_uuid
        lport.switch.port_count = port_count
        return lport


class TestOptimizedNVPDriverDeleteNetwork(TestOptimizedNVPDriver):
    '''Need to ensure that network of X switches deletes X switches.'''
    @contextlib.contextmanager
    def _stubs(self, switch_count=1):
        with contextlib.nested(
            mock.patch("%s.get_connection" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (get_connection, select_switch, get_switches):
            connection = self._create_connection()
            switch = self._create_lswitch_mock()
            get_connection.return_value = connection
            select_switch.return_value = switch
            get_switches.return_value = [switch] * switch_count
            self.context.session.delete = mock.Mock(return_value=None)
            yield connection, self.context.session.delete

    def test_delete_network_no_switches(self):
        '''Testing that X switches deleted with X switches; X = 0.'''
        switch_count = 0
        with self._stubs(
                switch_count=switch_count
        ) as (connection, context_delete):
            self.driver.delete_network(self.context, self.net_id)
            self.assertEquals(switch_count,
                              connection.lswitch().delete.call_count)
            self.assertEquals(switch_count, context_delete.call_count)

    def test_delete_network_single_switch(self):
        '''Testing that X switches deleted with X switches; X = 1.'''
        switch_count = 1
        with self._stubs(
                switch_count=switch_count
        ) as (connection, context_delete):
            self.driver.delete_network(self.context, self.net_id)
            self.assertEquals(switch_count,
                              connection.lswitch().delete.call_count)
            self.assertEquals(switch_count, context_delete.call_count)

    def test_delete_network_multi_switch(self):
        '''Testing that X switches deleted with X switches; X > 1.'''
        switch_count = 3
        with self._stubs(
                switch_count=switch_count
        ) as (connection, context_delete):
            self.driver.delete_network(self.context, self.net_id)
            self.assertEquals(switch_count,
                              connection.lswitch().delete.call_count)
            self.assertEquals(switch_count, context_delete.call_count)


class TestOptimizedNVPDriverDeletePort(TestOptimizedNVPDriver):
    '''Need to test if ports on switch = 0 delete switch.'''
    @contextlib.contextmanager
    def _stubs(self, port_count=2):
        with contextlib.nested(
            mock.patch("%s.get_connection" % self.d_pkg),
            mock.patch("%s._lport_select_by_id" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
        ) as (get_connection, select_port, select_switch):
            connection = self._create_connection()
            port = self._create_lport_mock(port_count)
            switch = self._create_lswitch_mock()
            get_connection.return_value = connection
            select_port.return_value = port
            select_switch.return_value = switch
            self.context.session.delete = mock.Mock(return_value=None)
            yield connection, self.context.session.delete

    def test_delete_ports_not_empty(self):
        '''Ensure that the switch is not deleted if ports exist.'''
        with self._stubs() as (connection, context_delete):
            self.driver.delete_port(self.context, self.port_id)
            self.assertEquals(1, context_delete.call_count)
            self.assertFalse(connection.lswitch().delete.called)
            self.assertTrue(connection.lswitch_port().delete.called)

    def test_delete_ports_is_empty(self):
        '''Ensure that the switch is deleted if empty.'''
        with self._stubs(port_count=1) as (connection, context_delete):
            self.driver.delete_port(self.context, self.port_id)
            self.assertEquals(2, context_delete.call_count)
            self.assertTrue(connection.lswitch_port().delete.called)
            self.assertTrue(connection.lswitch().delete.called)


class TestOptimizedNVPDriverCreatePort(TestOptimizedNVPDriver):
    '''In no case should the optimized driver query for an lswitch.'''
    @contextlib.contextmanager
    def _stubs(self, has_lswitch=True, maxed_ports=False):
        with contextlib.nested(
            mock.patch("%s.get_connection" % self.d_pkg),
            mock.patch("%s._lswitch_select_free" % self.d_pkg),
            mock.patch("%s._lswitch_select_first" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitch_create_optimized" % self.d_pkg),
            mock.patch("%s._get_network_details" % self.d_pkg)
        ) as (get_connection, select_free, select_first,
              select_by_id, create_opt, get_net_dets):
            connection = self._create_connection()
            get_connection.return_value = connection
            if has_lswitch:
                select_first.return_value = mock.Mock(nvp_id=self.lswitch_uuid)
            if not has_lswitch:
                select_first.return_value = None
                select_free.return_value = None
            elif not maxed_ports:
                select_free.return_value = self._create_lswitch_mock()
            else:
                select_free.return_value = None

            select_by_id.return_value = self._create_lswitch_mock()
            get_net_dets.return_value = dict(foo=3)
            yield connection, create_opt

    def test_create_port_and_maxed_switch_spanning(self):
        '''Testing to ensure a switch is made when maxed.'''
        with self._stubs(maxed_ports=True) as (
                connection, create_opt):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_port_and_create_switch_spanning(self):
        '''Testing to ensure a switch is made when no switch available.'''
        with self._stubs(has_lswitch=False) as (connection, create_opt):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_port_and_no_create_switch_spanning(self):
        '''Testing to ensure a switch is not made when max ports not met.'''
        with self._stubs() as (connection, create_opt):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertFalse(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_disabled_port_and_no_create_switch_spanning(self):
        '''Testing to ensure a port is made and disabled.'''
        with self._stubs() as (connection, create_opt):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id, False)
            self.assertTrue("uuid" in port)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertFalse(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(False in status_args)

    def test_create_port_and_create_switch(self):
        '''Testing to ensure a switch is made when no switch available.'''
        with self._stubs(has_lswitch=False) as (connection, create_opt):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_port_and_no_create_switch(self):
        '''Testing to ensure a switch is not made when available.'''
        with self._stubs() as (connection, create_opt):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertFalse(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(True in status_args)

    def test_create_disabled_port_and_no_create_switch(self):
        '''Testing to ensure a port is made and disabled.'''
        with self._stubs() as (connection, create_opt):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id, False)
            self.assertTrue("uuid" in port)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertFalse(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = connection.lswitch_port().\
                admin_status_enabled.call_args
            self.assertTrue(False in status_args)
