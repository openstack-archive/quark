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

import aiclib

import contextlib

import mock

import quark.db.models
import quark.drivers.optimized_nvp_driver
import quark.tests.test_nvp_driver as test_nvp_driver


class TestOptimizedNVPDriver(test_nvp_driver.TestNVPDriver):
    def setUp(self):
        if not hasattr(self, 'driver'):
            self.driver = (
                quark.drivers.optimized_nvp_driver.OptimizedNVPDriver())
        super(TestOptimizedNVPDriver, self).setUp()
        self.d_pkg = "quark.drivers.optimized_nvp_driver.OptimizedNVPDriver"
        self.context.session.add = mock.Mock(return_value=None)
        self.net_id = "12345678-1234-0000-1234-123412341234"

    def _create_lswitch_mock(self):
        lswitch = mock.Mock(id=self.lswitch_uuid, port_count=1,
                            network_id=self.net_id)
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
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (conn, select_switch, get_switches):
            connection = self._create_connection()
            switch = self._create_lswitch_mock()
            conn.return_value = connection
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
            self.assertEqual(switch_count,
                             connection.lswitch().delete.call_count)
            self.assertEqual(switch_count, context_delete.call_count)

    def test_delete_network_single_switch(self):
        '''Testing that X switches deleted with X switches; X = 1.'''
        switch_count = 1
        with self._stubs(
                switch_count=switch_count
        ) as (connection, context_delete):
            self.driver.delete_network(self.context, self.net_id)
            self.assertEqual(switch_count,
                             connection.lswitch().delete.call_count)
            self.assertEqual(switch_count, context_delete.call_count)

    def test_delete_network_multi_switch(self):
        '''Testing that X switches deleted with X switches; X > 1.'''
        switch_count = 3
        with self._stubs(
                switch_count=switch_count
        ) as (connection, context_delete):
            self.driver.delete_network(self.context, self.net_id)
            self.assertEqual(switch_count,
                             connection.lswitch().delete.call_count)
            self.assertEqual(switch_count, context_delete.call_count)


class TestOptimizedNVPDriverDeleteNetworkWithExceptions(
        TestOptimizedNVPDriver):
    '''Test for storage of orphaned nets from NVP or our quark db tables.'''

    @contextlib.contextmanager
    def _stubs(self, switch_count=1, error_code=500):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
            mock.patch("%s._lswitch_delete" % self.d_pkg)
        ) as (conn, select_switch, get_switches, delete_switch):
            connection = self._create_connection()
            switch = self._create_lswitch_mock()
            conn.return_value = connection
            select_switch.return_value = switch
            get_switches.return_value = [switch] * switch_count
            delete_switch.side_effect = aiclib.core.AICException(
                error_code, 'foo')
            self.context.session.delete = mock.Mock(return_value=None)
            self.context.session.add = mock.Mock(return_value=None)
            yield (connection, self.context.session.delete,
                   self.context.session.add, delete_switch)

    def test_delete_network_with_404_aicexception(self):
        with self._stubs(error_code=404) as (
                connection, session_delete_network_from_db,
                session_add_orphaned_network_to_db, nvp_delete_switch):
            self.driver.delete_network(self.context, self.net_id)
            self.assertEqual(1, nvp_delete_switch.call_count)
            self.assertEqual(1, session_delete_network_from_db.call_count)
            self.assertEqual(0, session_add_orphaned_network_to_db.call_count)

    def test_delete_network_with_non_404_aicexception(self):
        with self._stubs() as (
                connection, session_delete_network_from_db,
                session_add_orphaned_network_to_db, nvp_delete_switch):
            self.driver.delete_network(self.context, self.net_id)
            self.assertEqual(1, nvp_delete_switch.call_count)
            self.assertEqual(1, session_delete_network_from_db.call_count)
            self.assertEqual(1, session_add_orphaned_network_to_db.call_count)


class TestOptimizedNVPDriverDeletePortMultiSwitch(TestOptimizedNVPDriver):
    '''Test for 0 ports on the switch, and the switch not last in network.

    Need to test if ports on switch = 0 and delete the switch if it is not
    the last switch on the network.
    '''

    @contextlib.contextmanager
    def _stubs(self, port_count=2, exception=None):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lport_select_by_id" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
            mock.patch("%s._lport_delete" % self.d_pkg),
        ) as (conn, select_port, select_switch,
              two_switch, port_delete):
            connection = self._create_connection()
            port = self._create_lport_mock(port_count)
            switch = self._create_lswitch_mock()
            conn.return_value = connection
            select_port.return_value = port
            select_switch.return_value = switch
            two_switch.return_value = [switch, switch]
            self.context.session.delete = mock.Mock(return_value=None)
            if exception:
                port_delete.side_effect = exception
            yield (connection, self.context.session.delete,
                   self.context.session.add, port_delete)

    def test_delete_ports_not_empty(self):
        '''Ensure that the switch is not deleted if ports exist.'''
        with self._stubs() as (
                connection, context_delete, context_add, port_delete):
            self.driver.delete_port(self.context, self.port_id)
            self.assertEqual(1, context_delete.call_count)
            self.assertTrue(port_delete.called)
            self.assertFalse(connection.lswitch().delete.called)

    def test_delete_ports_is_empty(self):
        '''Ensure that the switch is deleted if empty and not last switch.'''
        with self._stubs(port_count=1) as (
                connection, context_delete, context_add, port_delete):
            self.driver.delete_port(self.context, self.port_id)
            self.assertEqual(2, context_delete.call_count)
            self.assertTrue(port_delete.called)
            self.assertTrue(connection.lswitch().delete.called)

    def test_delete_ports_with_exception(self):
        '''Ensure that exception is handled/logged.'''
        e = Exception('foo')
        with self._stubs(exception=e) as (
                connection, context_delete, context_add, port_delete):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, self.port_id)
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "Exception not raised")
                self.assertEqual(1, context_delete.call_count)
                self.assertEqual(0, context_add.call_count)
                self.assertFalse(connection.lswitch_port().delete.called)
                self.assertFalse(connection.lswitch().delete.called)

    def test_delete_ports_with_404_aicexception(self):
        '''Ensure that exception is handled/logged.'''
        e = aiclib.core.AICException(404, 'foo')
        with self._stubs(exception=e) as (
                connection, context_delete, context_add, port_delete):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, self.port_id)
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertEqual(1, context_delete.call_count)
                self.assertEqual(0, context_add.call_count)
                self.assertFalse(connection.lswitch_port().delete.called)
                self.assertFalse(connection.lswitch().delete.called)

    def test_delete_ports_with_500_aicexception(self):
        '''Ensure that exception is handled/logged.'''
        e = aiclib.core.AICException(500, 'foo')
        with self._stubs(exception=e) as (
                connection, context_delete, context_add, port_delete):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, self.port_id)
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertEqual(1, context_delete.call_count)
                self.assertEqual(1, context_add.call_count)
                self.assertFalse(connection.lswitch_port().delete.called)
                self.assertFalse(connection.lswitch().delete.called)


class TestOptimizedNVPDriverDeletePortSingleSwitch(TestOptimizedNVPDriver):
    '''If ports on switch = 0, delete switch unless last on the network.'''

    @contextlib.contextmanager
    def _stubs(self, port_count=1):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lport_select_by_id" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (conn, select_port, select_switch, one_switch):
            connection = self._create_connection()
            switch = self._create_lswitch_mock()
            conn.return_value = connection
            select_port.return_value = None
            select_switch.return_value = switch
            one_switch.return_value = [switch]
            self.context.session.delete = mock.Mock(return_value=None)
            yield connection, self.context.session.delete

    def test_delete_ports_is_empty(self):
        '''Ensure that the switch is not deleted if it is the last.'''
        with self._stubs(port_count=1) as (connection, context_delete):
            self.driver.delete_port(self.context, self.port_id)
            self.assertEqual(0, context_delete.call_count)
            self.assertFalse(connection.lswitch_port().delete.called)


class TestOptimizedNVPDriverDeletePortMissing(TestOptimizedNVPDriver):
    '''If ports on switch = 0, delete switch unless last on the network.'''

    @contextlib.contextmanager
    def _stubs(self, port_count=2):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lport_select_by_id" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (conn, select_port, select_switch, one_switch):
            connection = self._create_connection()
            port = self._create_lport_mock(port_count)
            switch = self._create_lswitch_mock()
            conn.return_value = connection
            select_port.return_value = port
            select_switch.return_value = switch
            one_switch.return_value = [switch]
            self.context.session.delete = mock.Mock(return_value=None)
            yield connection, self.context.session.delete

    def test_delete_ports_is_empty(self):
        '''Ensure that the switch is not deleted if it is the last.'''
        with self._stubs(port_count=1) as (connection, context_delete):
            self.driver.delete_port(self.context, self.port_id)
            self.assertEqual(1, context_delete.call_count)
            self.assertTrue(connection.lswitch_port().delete.called)
            self.assertFalse(connection.lswitch().delete.called)


class TestOptimizedNVPDriverCreatePort(TestOptimizedNVPDriver):
    '''In no case should the optimized driver query for an lswitch.'''

    @contextlib.contextmanager
    def _stubs(self, has_lswitch=True, maxed_ports=False):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lswitch_select_free" % self.d_pkg),
            mock.patch("%s._lswitch_select_first" % self.d_pkg),
            mock.patch("%s._lswitch_select_by_nvp_id" % self.d_pkg),
            mock.patch("%s._lswitch_create_optimized" % self.d_pkg),
            mock.patch("%s._get_network_details" % self.d_pkg)
        ) as (conn, select_free, select_first,
              select_by_id, create_opt, get_net_dets):
            connection = self._create_connection()
            conn.return_value = connection
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

    def test_select_ipam_strategy(self):
        strategy = self.driver.select_ipam_strategy(1, "ANY")
        self.assertEqual(strategy, "ANY")

    def test_create_port_and_maxed_switch_spanning(self):
        '''Testing to ensure a switch is made when maxed.'''
        with self._stubs(maxed_ports=True) as (
                connection, create_opt):
            self.driver.limits['max_ports_per_switch'] = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(create_opt.called)
            self.assertFalse(connection.lswitch().query.called)
            status_args, kwargs = self.context.session.add.call_args
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
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
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
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
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
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
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
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
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
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
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
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
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(False in status_args)


class TestOptimizedNVPDriverUpdatePort(TestOptimizedNVPDriver):
    def test_update_port(self):
        mod_path = "quark.drivers.%s"
        op_path = "optimized_nvp_driver.OptimizedNVPDriver"
        lport_path = "%s._lport_select_by_id" % op_path
        with contextlib.nested(
            mock.patch(mod_path % "nvp_driver.NVPDriver.update_port"),
            mock.patch(mod_path % lport_path),
        ) as (update_port, port_find):
            ret_port = quark.drivers.optimized_nvp_driver.LSwitchPort()
            port_find.return_value = ret_port
            update_port.return_value = dict(switch_id=2)
            self.driver.update_port(self.context, 1)
            self.assertEqual(ret_port.switch_id, 2)


class TestCreateSecurityGroups(TestOptimizedNVPDriver):
    def test_create_security_group(self):
        with mock.patch("%s._connection" % self.d_pkg):
            self.driver.create_security_group(self.context, "newgroup")
            self.assertTrue(self.context.session.add.called)


class TestDeleteSecurityGroups(TestOptimizedNVPDriver):
    def test_delete_security_group(self):
        mod_path = "quark.drivers.nvp_driver.NVPDriver"
        with contextlib.nested(
                mock.patch("%s._connection" % self.d_pkg),
                mock.patch("%s._query_security_group" % self.d_pkg),
                mock.patch("%s.delete_security_group" % mod_path)):

            session_delete = self.context.session.delete
            self.context.session.delete = mock.Mock(return_value=None)
            self.driver.delete_security_group(self.context, 1)
            self.assertTrue(self.context.session.delete.called)
            self.context.session.delete = session_delete


class TestSecurityGroupRules(TestOptimizedNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, rules=None):
        rules = rules or []
        with contextlib.nested(
                mock.patch("%s._connection" % self.d_pkg),
                mock.patch("%s._query_security_group" % self.d_pkg),
                mock.patch("%s._check_rule_count_per_port" % self.d_pkg),
        ) as (conn, query_sec_group, rule_count):
            query_sec_group.return_value = (quark.drivers.optimized_nvp_driver.
                                            SecurityProfile())
            connection = self._create_connection()
            rule_count.return_value = 1
            connection.securityprofile = self._create_security_profile()
            connection.securityrule = self._create_security_rule()
            connection.lswitch_port().query.return_value = (
                self._create_lport_query(1, [self.profile_id]))
            conn.return_value = connection

            old_query = self.context.session.query
            sec_group = quark.db.models.SecurityGroup()
            for rule in rules:
                rule_mod = quark.db.models.SecurityGroupRule()
                rule_mod.update(rule)
                sec_group.rules.append(rule_mod)
            first_mock = mock.Mock()
            filter_mock = mock.Mock()
            self.context.session.query = mock.Mock(return_value=filter_mock)
            filter_mock.filter.return_value = first_mock
            first_mock.first.return_value = sec_group

            yield connection
            self.context.session.query = old_query

    def test_security_rule_create_no_rules(self):
        with self._stubs() as connection:
            self.driver.create_security_group_rule(
                self.context, 1,
                {'ethertype': 'IPv4', 'direction': 'ingress'})
            connection.securityprofile().assert_has_calls([
                mock.call.port_ingress_rules([{'ethertype': 'IPv4'}]),
                mock.call.update(),
            ], any_order=True)

    def test_security_rule_create(self):
        with self._stubs(rules=[{"direction": "ingress"}]) as connection:
            self.driver.create_security_group_rule(
                self.context, 1,
                {'ethertype': 'IPv4', 'direction': 'ingress'})
            connection.securityprofile().assert_has_calls([
                mock.call.port_ingress_rules([{}, {'ethertype': 'IPv4'}]),
                mock.call.update(),
            ], any_order=True)


class TestCreateLswitchOptimized(TestOptimizedNVPDriver):
    def test_create_lswitch_optimized(self):
        self.driver._lswitch_create_optimized(self.context, "public", 1, 1)
        self.assertTrue(self.context.session.add.called)


class TestGetNetworkDetails(TestOptimizedNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, switch):
        with mock.patch("%s._lswitch_select_first" % self.d_pkg) as lselect:
            switch_model = quark.drivers.optimized_nvp_driver.LSwitch()
            switch_model.update(switch)
            lselect.return_value = switch_model
            yield

    def test_get_network_details(self):
        switch = {"network_id": 2, "transport_zone": 1,
                  "transport_connector": "bridge", "segment_id": 3,
                  "display_name": "public"}
        expected = {"network_name": "public", "phys_net": 1,
                    "phys_type": "bridge", "segment_id": 3}
        with self._stubs(switch):
            switches = []
            details = self.driver._get_network_details(self.context, 1,
                                                       switches)
            for key in expected.keys():
                self.assertEqual(details[key], expected[key])


class TestQueryMethods(TestOptimizedNVPDriver):
    """These tests provide coverage on the query helpers.

    No serious assertions are made, as there's no sense in testing that
    sqlalchemy does in fact do what it's supposed to do.
    """

    @contextlib.contextmanager
    def _stubs(self):
        old_query = self.context.session.query
        self.context.session.query = mock.Mock()
        query_return = mock.MagicMock()
        self.context.session.query.return_value = query_return
        yield query_return
        self.context.session.query = old_query

    def test_lport_select_by_id(self):
        with self._stubs() as query_return:
            self.driver._lport_select_by_id(self.context, 1)
            self.assertTrue(query_return.filter.called)

    def test_lswitch_select_by_nvp_id(self):
        with self._stubs() as query_return:
            self.driver._lswitch_select_by_nvp_id(self.context, 1)
            self.assertTrue(query_return.filter.called)

    def test_lswitch_select_first(self):
        with self._stubs() as query_return:
            self.driver._lswitch_select_first(self.context, 1)
            self.assertTrue(query_return.filter.called)

            # NOTE(mdietz): This is probably pretty brittle, but I didn't want
            #               this patch going in without a test
            bin_expr = query_return.filter.__dict__["_mock_call_args"][0][0]
            children = bin_expr.get_children()
            self.assertEqual(str(children[0]),
                             "quark_nvp_driver_lswitch.network_id")

    def test_lswitch_select_free(self):
        with self._stubs() as query_return:
            self.driver._lswitch_select_free(self.context, 1)
            self.assertTrue(query_return.filter.called)

    def test_lswitches_for_network(self):
        with self._stubs() as query_return:
            self.driver._lswitches_for_network(self.context, 1)
            self.assertTrue(query_return.filter.called)

    def test_get_lswitch_ids_for_network(self):
        with self._stubs() as query_return:
            query_result = query_return.filter.return_value.all
            query_result.return_value = [{"nvp_id": "foo"}]
            ids = self.driver.get_lswitch_ids_for_network(self.context, 1)
            self.assertTrue(query_return.filter.called)
            self.assertEqual(ids, ["foo"])

    def test_lswitch_from_port(self):
        with self._stubs() as query_return:
            self.driver._lswitch_from_port(self.context, 1)
            self.assertTrue(query_return.filter.called)

    def test_query_security_group(self):
        with self._stubs() as query_return:
            self.driver._query_security_group(self.context, 1)
            self.assertTrue(query_return.filter.called)
