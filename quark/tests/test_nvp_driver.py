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
import neutron.extensions.securitygroup as sg_ext
from oslo_config import cfg

import quark.drivers.nvp_driver
from quark import exceptions as q_exc
from quark.tests import test_base


class TestNVPDriver(test_base.TestBase):
    def setUp(self):
        super(TestNVPDriver, self).setUp()
        cfg.CONF.set_override('environment_capabilities', [], 'QUARK')
        if not hasattr(self, 'driver'):
            self.driver = quark.drivers.nvp_driver.NVPDriver()
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')
        cfg.CONF.set_override('max_rules_per_group', 3, 'NVP')
        cfg.CONF.set_override('max_rules_per_port', 1, 'NVP')
        self.driver.max_ports_per_switch = 0

        self.lswitch_uuid = "12345678-1234-1234-1234-123456781234"
        self.context.tenant_id = "tid"
        self.lport_uuid = "12345678-0000-0000-0000-123456781234"
        self.net_id = "12345678-1234-1234-1234-123412341234"
        self.port_id = "12345678-0000-0000-0000-123412341234"
        self.profile_id = "12345678-0000-0000-0000-000000000000"
        self.d_pkg = "quark.drivers.nvp_driver.NVPDriver"
        self.max_spanning = 3
        self.driver.limits.update({'max_rules_per_group': 3,
                                   'max_rules_per_port': 2})

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
        port.attachment_vif = mock.Mock()
        return port

    def _create_lport_query(self, switch_count, profiles=[]):
        query = mock.Mock()
        port_list = {"_relations":
                     {"LogicalSwitchConfig":
                      {"uuid": self.lswitch_uuid,
                       "security_profiles": profiles}}}
        port_query = {"results": [port_list], "result_count": switch_count}
        query.results = mock.Mock(return_value=port_query)
        query.security_profile_uuid().results.return_value = {
            "results": [{"security_profiles": profiles}]}
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
                                 'lport_count': port_count}}}]
        if not switches_available:
            lswitch_list = []
        lswitch_query = {"results": lswitch_list}
        query.relations = mock.Mock(return_value=None)
        query.results = mock.Mock(return_value=lswitch_query)
        return query

    def _create_security_profile(self):
        profile = mock.Mock()
        query = mock.Mock()
        group = {'name': 'foo', 'uuid': self.profile_id,
                 'logical_port_ingress_rules': [],
                 'logical_port_egress_rules': []}
        query.results = mock.Mock(return_value={'results': [group],
                                                'result_count': 1})
        profile.query = mock.Mock(return_value=query)
        profile.read = mock.Mock(return_value=group)
        return mock.Mock(return_value=profile)

    def _create_security_rule(self, rule={}):
        return lambda *x, **y: dict(y, ethertype=x[0])


class TestNVPDriverCreateNetwork(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
        ) as (conn,):
            connection = self._create_connection()
            conn.return_value = connection
            yield connection

    def test_create_network(self):
        with self._stubs() as (connection):
            self.driver.create_network(self.context, "test")
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch().transport_zone.called)

    def test_create_network_name_longer_than_40_chars_gets_trimmed(self):
        with self._stubs() as (connection):
            long_n = 'A' * 50
            self.driver.create_network(self.context, long_n)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch().transport_zone.called)
            connection.lswitch().display_name.assert_called_with(long_n[:40])


class TestNVPDriverDefaultTransportZoneBindings(TestNVPDriver):

    def setUp(self):
        super(TestNVPDriverDefaultTransportZoneBindings, self).setUp()
        cfg.CONF.set_override(
            'additional_default_tz_types', ['vxlan'], 'NVP')
        cfg.CONF.set_override(
            'default_tz', 'tz_uuid', 'NVP')
        cfg.CONF.set_override(
            'default_tz_type', 'stt', 'NVP')

    def tearDown(self):
        super(TestNVPDriverDefaultTransportZoneBindings, self).setUp()
        cfg.CONF.clear_override('additional_default_tz_types', 'NVP')
        cfg.CONF.clear_override('default_tz', 'NVP')
        cfg.CONF.clear_override('default_tz_type', 'NVP')

    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("quark.drivers.nvp_driver.SA_REGISTRY."
                       "get_strategy"),
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (sa_get_strategy, conn, switch_list):
            connection = self._create_connection()
            conn.return_value = connection

            ret = {"results": [{"uuid": self.lswitch_uuid}]}
            switch_list().results = mock.Mock(return_value=ret)

            sa_strategy = mock.Mock()
            sa_get_strategy.return_value = sa_strategy
            sa_strategy.allocate.return_value = {"id": 123}

            yield sa_get_strategy, sa_strategy, connection

    def test_default_tz_bindings_net_create(self):
        with self._stubs() as (sa_get_strategy, sa_strategy, connection):
            self.driver.create_network(
                self.context, "test", network_id="network_id")

            self.assertTrue(connection.lswitch().create.called)

            # assert vxlan tz manager was called
            sa_strategy.allocate.assert_called_once_with(
                self.context, 'tz_uuid', 'network_id')

            # assert transport_zone was called:
            # once for the default configured tz type (stt)
            # once for the additional default tz type (vxlan)
            self.assertEqual(
                connection.lswitch().transport_zone.call_args_list,
                [mock.call('tz_uuid', 'stt'),
                 mock.call('tz_uuid', 'vxlan', vxlan_id=123)]
            )

    def test_default_tz_bindings_net_delete(self):
        with self._stubs() as (sa_get_strategy, sa_strategy, connection):
            self.driver.delete_network(self.context, "network_id")
            self.assertTrue(connection.lswitch().delete.called)

            sa_strategy.deallocate.assert_called_once_with(
                self.context, 'tz_uuid', 'network_id')


class TestNVPDriverProviderNetwork(TestNVPDriver):
    """Testing all of the network types is unnecessary, but a nice have."""

    @contextlib.contextmanager
    def _stubs(self, tz):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
        ) as (conn,):
            connection = self._create_connection()
            switch = self._create_lswitch(1, False)
            switch.transport_zone = mock.Mock()
            tz_results = mock.Mock()
            tz_results.results = mock.Mock(return_value=tz)
            tz_query = mock.Mock()
            tz_query.query = mock.Mock(return_value=tz_results)
            connection.transportzone = mock.Mock(return_value=tz_query)
            conn.return_value = connection
            yield connection, switch

    def test_config_provider_attrs_flat_net(self):
        tz = dict(result_count=1)
        with self._stubs(tz) as (connection, switch):
            self.driver._config_provider_attrs(
                connection=connection, switch=switch, phys_net="net_uuid",
                net_type="flat", segment_id=None)
            switch.transport_zone.assert_called_with(
                zone_uuid="net_uuid", transport_type="bridge", vlan_id=None)

    def test_config_provider_attrs_vlan_net(self):
        tz = dict(result_count=1)
        with self._stubs(tz) as (connection, switch):
            self.driver._config_provider_attrs(
                connection=connection, switch=switch, phys_net="net_uuid",
                net_type="vlan", segment_id=10)
            switch.transport_zone.assert_called_with(
                zone_uuid="net_uuid", transport_type="bridge", vlan_id=10)

    def test_config_provider_attrs_gre_net(self):
        tz = dict(result_count=1)
        with self._stubs(tz) as (connection, switch):
            self.driver._config_provider_attrs(
                connection=connection, switch=switch, phys_net="net_uuid",
                net_type="gre", segment_id=None)
            switch.transport_zone.assert_called_with(
                zone_uuid="net_uuid", transport_type="gre", vlan_id=None)

    def test_config_provider_attrs_stt_net(self):
        tz = dict(result_count=1)
        with self._stubs(tz) as (connection, switch):
            self.driver._config_provider_attrs(
                connection=connection, switch=switch, phys_net="net_uuid",
                net_type="stt", segment_id=None)
            switch.transport_zone.assert_called_with(
                zone_uuid="net_uuid", transport_type="stt", vlan_id=None)

    def test_config_provider_attrs_local_net(self):
        tz = dict(result_count=1)
        with self._stubs(tz) as (connection, switch):
            self.driver._config_provider_attrs(
                connection=connection, switch=switch, phys_net="net_uuid",
                net_type="local", segment_id=None)
            switch.transport_zone.assert_called_with(
                zone_uuid="net_uuid", transport_type="local", vlan_id=None)

    def test_config_provider_attrs_bridge_net(self):
        """A specialized case for NVP

        This exists because internal driver calls can also call this method,
        and they may pass bridge in as the type as that's how it's known
        to NVP.
        """

        tz = dict(result_count=1)
        with self._stubs(tz) as (connection, switch):
            self.driver._config_provider_attrs(
                connection=connection, switch=switch, phys_net="net_uuid",
                net_type="bridge", segment_id=None)
            switch.transport_zone.assert_called_with(
                zone_uuid="net_uuid", transport_type="bridge", vlan_id=None)

    def test_config_provider_attrs_no_phys_net_or_type(self):
        with self._stubs({}) as (connection, switch):
            self.driver._config_provider_attrs(
                connection=connection, switch=switch, phys_net=None,
                net_type=None, segment_id=None)
            self.assertFalse(switch.transport_zone.called)

    def test_config_provider_attrs_vlan_net_no_segment_id_fails(self):
        with self._stubs({}) as (connection, switch):
            self.assertRaises(
                q_exc.SegmentIdRequired,
                self.driver._config_provider_attrs, connection=connection,
                switch=switch, phys_net="net_uuid", net_type="vlan",
                segment_id=None)

    def test_config_provider_attrs_non_vlan_net_with_segment_id_fails(self):
        with self._stubs({}) as (connection, switch):
            self.assertRaises(
                q_exc.SegmentIdUnsupported,
                self.driver._config_provider_attrs, connection=connection,
                switch=switch, phys_net="net_uuid", net_type="flat",
                segment_id=10)

    def test_config_phys_net_no_phys_type_fails(self):
        with self._stubs({}) as (connection, switch):
            self.assertRaises(
                q_exc.ProvidernetParamError,
                self.driver._config_provider_attrs, connection=connection,
                switch=switch, phys_net="net_uuid", net_type=None,
                segment_id=None)

    def test_config_no_phys_net_with_phys_type_fails(self):
        with self._stubs({}) as (connection, switch):
            self.assertRaises(
                q_exc.ProvidernetParamError,
                self.driver._config_provider_attrs, connection=connection,
                switch=switch, phys_net=None, net_type="flat",
                segment_id=None)

    def test_config_physical_net_doesnt_exist_fails(self):
        tz = dict(result_count=0)
        with self._stubs(tz) as (connection, switch):
            self.assertRaises(
                q_exc.PhysicalNetworkNotFound,
                self.driver._config_provider_attrs, connection=connection,
                switch=switch, phys_net="net_uuid", net_type="flat",
                segment_id=None)

    def test_config_physical_net_bad_net_type_fails(self):
        with self._stubs({}) as (connection, switch):
            self.assertRaises(
                q_exc.InvalidPhysicalNetworkType,
                self.driver._config_provider_attrs, connection=connection,
                switch=switch, phys_net="net_uuid", net_type="lol",
                segment_id=None)


class TestNVPDriverDeleteNetwork(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, network_exists=True):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
        ) as (conn, switch_list):
            connection = self._create_connection()
            conn.return_value = connection
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

    def test_delete_network_not_exists_404_exception(self):
        with self._stubs(network_exists=True) as (connection):
            self.driver.delete_network(self.context, "test")
            self.assertTrue(connection.lswitch().delete.called)


class TestNVPDriverDeleteNetworkWithExceptions(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, network_exists=True, exception=None):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
            mock.patch("%s._lswitch_delete" % self.d_pkg),
        ) as (conn, switch_list, switch_delete):
            connection = self._create_connection()
            conn.return_value = connection
            if network_exists:
                ret = {"results": [{"uuid": self.lswitch_uuid}]}
            else:
                ret = {"results": []}
            switch_list().results = mock.Mock(return_value=ret)
            if exception:
                switch_delete.side_effect = exception
            yield connection

    def test_delete_network_with_404_aicexception(self):
        e = aiclib.core.AICException(404, 'foo')
        with self._stubs(exception=e) as connection:
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_network(self.context, "test")
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertFalse(connection.lswitch().delete.called)

    def test_delete_network_with_500_aicexception(self):
        e = aiclib.core.AICException(500, 'foo')
        with self._stubs(exception=e) as connection:
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_network(self.context, "test")
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertFalse(connection.lswitch().delete.called)

    def test_delete_network_with_normal_exception(self):
        e = StandardError('foo')
        with self._stubs(exception=e) as connection:
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_network(self.context, "test")
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "StandardError not raised")
                self.assertFalse(connection.lswitch().delete.called)


class TestNVPDriverCreatePort(TestNVPDriver):
    '''In all cases an lswitch should be queried.'''
    @contextlib.contextmanager
    def _stubs(self, has_lswitch=True, maxed_ports=False, net_details=None):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._next_connection" % self.d_pkg),
            mock.patch("%s._lswitches_for_network" % self.d_pkg),
            mock.patch("%s._get_network_details" % self.d_pkg),
        ) as (conn, next_conn, get_switches, get_net_dets):
            connection = self._create_connection(has_switches=has_lswitch,
                                                 maxed_ports=maxed_ports)
            conn.return_value = connection
            get_switches.return_value = connection.lswitch().query()
            get_net_dets.return_value = net_details
            yield connection

    def test_select_ipam_strategy(self):
        strategy = self.driver.select_ipam_strategy(1, "ANY")
        self.assertEqual(strategy, "ANY")

    def test_create_port_switch_exists(self):
        with self._stubs(net_details=dict(foo=3)) as (connection):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch_port().attachment_vif.called)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(True in status_args)

    def test_create_port_switch_exists_tags(self):
        with self._stubs(net_details=dict(foo=3)) as (connection):
            device_id = "foo"
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id, device_id=device_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch_port().attachment_vif.called)
            self.assertFalse(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(True in status_args)
            connection.lswitch_port().assert_has_calls([mock.call.tags([
                dict(scope="neutron_net_id", tag=self.net_id),
                dict(scope="neutron_port_id", tag=self.port_id),
                dict(scope="os_tid", tag=self.context.tenant_id),
                dict(scope="vm_id", tag=device_id)
            ])], any_order=True)

    def test_create_port_switch_not_exists(self):
        with self._stubs(has_lswitch=False,
                         net_details=dict(foo=3)) as (connection):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(True in status_args)

    def test_create_port_no_existing_switches_fails(self):
        with self._stubs(has_lswitch=False):
            self.assertRaises(q_exc.BadNVPState, self.driver.create_port,
                              self.context, self.net_id, self.port_id, False)

    def test_create_disabled_port_switch_not_exists(self):
        with self._stubs(has_lswitch=False,
                         net_details=dict(foo=3)) as (connection):
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id, False)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(False in status_args)

    def test_create_port_switch_exists_spanning(self):
        with self._stubs(maxed_ports=True,
                         net_details=dict(foo=3)) as (connection):
            self.driver.limits['max_ports_per_switch'] = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(True in status_args)

    def test_create_port_switch_not_exists_spanning(self):
        with self._stubs(has_lswitch=False, maxed_ports=True,
                         net_details=dict(foo=3)) as (connection):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(True in status_args)

    def test_create_disabled_port_switch_not_exists_spanning(self):
        with self._stubs(has_lswitch=False, maxed_ports=True,
                         net_details=dict(foo=3)) as (connection):
            self.driver.max_ports_per_switch = self.max_spanning
            port = self.driver.create_port(self.context, self.net_id,
                                           self.port_id, False)
            self.assertTrue("uuid" in port)
            self.assertTrue(connection.lswitch().create.called)
            self.assertTrue(connection.lswitch_port().create.called)
            self.assertTrue(connection.lswitch().query.called)
            status_args, kwargs = (
                connection.lswitch_port().admin_status_enabled.call_args)
            self.assertTrue(False in status_args)

    def test_create_port_with_security_groups(self):
        cfg.CONF.set_override('environment_capabilities', [], 'QUARK')
        with self._stubs() as connection:
            connection.securityprofile = self._create_security_profile()
            self.driver.create_port(self.context, self.net_id,
                                    self.port_id,
                                    security_groups=[1])
            connection.lswitch_port().assert_has_calls([
                mock.call.security_profiles([self.profile_id]),
            ], any_order=True)
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')

    def test_create_port_with_security_groups_max_rules(self):
        cfg.CONF.set_override('environment_capabilities', [], 'QUARK')
        with self._stubs() as connection:
            connection.securityprofile = self._create_security_profile()
            connection.securityprofile().read().update(
                {'logical_port_ingress_rules': [{'ethertype': 'IPv4'},
                                                {'ethertype': 'IPv6'}],
                 'logical_port_egress_rules': [{'ethertype': 'IPv4'},
                                               {'ethertype': 'IPv6'}]})
            with self.assertRaises(sg_ext.nexception.InvalidInput):
                self.driver.create_port(
                    self.context, self.net_id, self.port_id,
                    security_groups=[1])
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')


class TestNVPDriverUpdatePort(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._next_connection" % self.d_pkg),
        ) as (conn, next_conn):
            connection = self._create_connection()
            connection.securityprofile = self._create_security_profile()
            conn.return_value = connection
            yield connection

    def test_update_port(self):
        cfg.CONF.set_override('environment_capabilities', [], 'QUARK')
        with self._stubs() as connection:
            self.driver.update_port(
                self.context, self.port_id,
                security_groups=[1])
            connection.lswitch_port().assert_has_calls([
                mock.call.security_profiles([self.profile_id]),
            ], any_order=True)
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')

    def test_update_port_max_rules(self):
        cfg.CONF.set_override('environment_capabilities', [], 'QUARK')
        with self._stubs() as connection:
            connection.securityprofile().read().update(
                {'logical_port_ingress_rules': [{'ethertype': 'IPv4'},
                                                {'ethertype': 'IPv6'}],
                 'logical_port_egress_rules': [{'ethertype': 'IPv4'},
                                               {'ethertype': 'IPv6'}]})
            with self.assertRaises(sg_ext.nexception.InvalidInput):
                self.driver.update_port(
                    self.context, self.port_id,
                    security_groups=[1])
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')


class TestNVPDriverLswitchesForNetwork(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, single_switch=True):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
        ) as (conn,):
            connection = self._create_connection(
                has_switches=True, switch_count=1)
            conn.return_value = connection
            yield connection

    def test_get_lswitches(self):
        """Test exists for coverage. No decisions are made."""
        with self._stubs() as connection:
            query_mock = mock.Mock()
            query_mock.tags = mock.Mock()
            query_mock.tagscopes = mock.Mock()
            connection.query = mock.Mock(return_value=query_mock)
            self.driver._lswitches_for_network(self.context, "net_uuid")

    def test_get_lswitch_ids_for_network(self):
        with self._stubs() as connection:
            query_mock = mock.Mock()
            query_mock.tags = mock.Mock()
            query_mock.tagscopes = mock.Mock()
            connection.query = mock.Mock(return_value=query_mock)
            lswitch_ids = self.driver.get_lswitch_ids_for_network(
                self.context, "net_uuid")
            self.assertEqual(lswitch_ids, ['abcd'])


class TestSwitchCopying(TestNVPDriver):
    def test_no_existing_switches(self):
        switches = dict(results=[])
        args = self.driver._get_network_details(None, 1, switches)
        self.assertTrue(args == {})

    def test_has_switches_no_transport_zones(self):
        switch = dict(display_name="public", transport_zones=[])
        switches = dict(results=[switch])
        args = self.driver._get_network_details(None, 1, switches)
        self.assertEqual(args["network_name"], "public")
        self.assertEqual(args["phys_net"], None)

    def test_has_switches_and_transport_zones(self):
        transport_zones = [dict(zone_uuid="zone_uuid",
                                transport_type="bridge")]
        switch = dict(display_name="public", transport_zones=transport_zones)
        switches = dict(results=[switch])
        args = self.driver._get_network_details(None, 1, switches)
        self.assertEqual(args["network_name"], "public")
        self.assertEqual(args["phys_net"], "zone_uuid")
        self.assertEqual(args["phys_type"], "bridge")

    def test_has_switches_tz_and_vlan(self):
        binding = dict(vlan_translation=[dict(transport=10)])
        transport_zones = [dict(zone_uuid="zone_uuid",
                                transport_type="bridge",
                                binding_config=binding)]
        switch = dict(display_name="public", transport_zones=transport_zones)
        switches = dict(results=[switch])
        args = self.driver._get_network_details(None, 1, switches)
        self.assertEqual(args["network_name"], "public")
        self.assertEqual(args["phys_net"], "zone_uuid")
        self.assertEqual(args["phys_type"], "bridge")


class TestNVPDriverDeletePort(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, switch_count=1):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._next_connection" % self.d_pkg),
        ) as (conn, next_conn):
            connection = self._create_connection(switch_count=switch_count)
            conn.return_value = connection
            yield connection

    def test_delete_port(self):
        with self._stubs() as (connection):
            self.driver.delete_port(self.context, self.port_id)
            self.assertTrue(connection.lswitch_port().delete.called)

    def test_delete_port_switch_given(self):
        with self._stubs() as (connection):
            self.driver.delete_port(self.context, self.port_id,
                                    lswitch_uuid=self.lswitch_uuid)
            self.assertFalse(connection.lswitch_port().query.called)
            self.assertTrue(connection.lswitch_port().delete.called)

    def test_delete_port_many_switches(self):
        with self._stubs(switch_count=2):
            try:
                with self.assertRaises(Exception):  # noqa
                    self.driver.delete_port(self.context, self.port_id)
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "Exception not raised")

    def test_delete_port_no_switch_bad_data(self):
        with self._stubs(switch_count=0):
            try:
                with self.assertRaises(Exception):  # noqa
                    self.driver.delete_port(self.context, self.port_id)
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "Exception not raised")


class TestNVPDriverDeletePortWithExceptions(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, switch_exception=None, delete_exception=None):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._lswitch_from_port" % self.d_pkg),
        ) as (conn, switch):
            connection = self._create_connection()
            conn.return_value = connection
            if switch_exception:
                switch.side_effect = switch_exception
            else:
                switch = mock.Mock(return_value=1)
            if delete_exception:
                connection.lswitch_port.delete.side_effect = delete_exception
            yield connection

    def test_delete_port_with_switch_query_general_exception(self):
        e = Exception('foo')
        with self._stubs(switch_exception=e) as (connection):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, 'test')
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "Exception not raised")
                self.assertFalse(connection.lswitch_port().delete.called)

    def test_delete_port_with_switch_query_404_aic_exception(self):
        e = aiclib.core.AICException(404, 'foo')
        with self._stubs(switch_exception=e) as (connection):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, 'test')
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertFalse(connection.lswitch_port().delete.called)

    def test_delete_port_with_switch_query_500_aic_exception(self):
        e = aiclib.core.AICException(500, 'foo')
        with self._stubs(switch_exception=e) as (connection):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, 'test')
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertFalse(connection.lswitch_port().delete.called)

    def test_delete_port_with_delete_general_exception(self):
        e = Exception('foo')
        with self._stubs(delete_exception=e) as (connection):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, 'test')
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "Exception not raised")
                self.assertTrue(connection.lswitch_port().delete.called)

    def test_delete_port_with_delete_404_aic_exception(self):
        e = aiclib.core.AICException(404, 'foo')
        with self._stubs(delete_exception=e) as (connection):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, 'test')
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertTrue(connection.lswitch_port().delete.called)

    def test_delete_port_with_delete_500_aic_exception(self):
        e = aiclib.core.AICException(500, 'foo')
        with self._stubs(delete_exception=e) as (connection):
            try:
                with self.assertRaises(type(e)):
                    self.driver.delete_port(self.context, 'test')
                self.fail("AssertionError should have been raised.")
            except AssertionError as ae:
                self.assertEqual(ae.args[0], "AICException not raised")
                self.assertTrue(connection.lswitch_port().delete.called)


class TestNVPDriverCreateSecurityGroup(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._next_connection" % self.d_pkg),
        ) as (conn, next_conn):
            connection = self._create_connection()
            connection.securityprofile = self._create_security_profile()
            conn.return_value = connection
            yield connection

    def test_security_group_create(self):
        group = {'group_id': 1}
        with self._stubs() as connection:
            self.driver.create_security_group(
                self.context, 'foo', **group)
            connection.securityprofile().assert_has_calls([
                mock.call.display_name('foo'),
                mock.call.create(),
            ], any_order=True)

    def test_security_group_create_with_rules(self):
        ingress_rules = [{'ethertype': 'IPv4'}, {'ethertype': 'IPv4',
                                                 'protocol': 6}]
        egress_rules = [{'ethertype': 'IPv6', 'protocol': 17}]
        group = {'group_id': 1, 'port_ingress_rules': ingress_rules,
                 'port_egress_rules': egress_rules}
        with self._stubs() as connection:
            self.driver.create_security_group(
                self.context, 'foo', **group)
            connection.securityprofile().assert_has_calls([
                mock.call.display_name('foo'),
                mock.call.port_egress_rules(egress_rules),
                mock.call.port_ingress_rules(ingress_rules),
                mock.call.tags([{'scope': 'neutron_group_id', 'tag': 1},
                                {'scope': 'os_tid',
                                 'tag': self.context.tenant_id}]),
            ], any_order=True)

    def test_security_group_create_rules_at_max(self):
        ingress_rules = [{'ethertype': 'IPv4', 'protocol': 6},
                         {'ethertype': 'IPv6',
                          'remote_ip_prefix': '192.168.0.1'}]
        egress_rules = [{'ethertype': 'IPv4', 'protocol': 17,
                         'port_range_min': 0, 'port_range_max': 100},
                        {'ethertype': 'IPv4', 'remote_group_id': 2}]
        with self._stubs():
            with self.assertRaises(sg_ext.nexception.InvalidInput):
                self.driver.create_security_group(
                    self.context, 'foo',
                    port_ingress_rules=ingress_rules,
                    port_egress_rules=egress_rules)


class TestNVPDriverDeleteSecurityGroup(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._next_connection" % self.d_pkg),
        ) as (conn, next_conn):
            connection = self._create_connection()
            connection.securityprofile = self._create_security_profile()
            conn.return_value = connection
            yield connection

    def test_security_group_delete(self):
        with self._stubs() as connection:
            self.driver.delete_security_group(self.context, 1)
            connection.securityprofile().query().assert_has_calls([
                mock.call.tagscopes(['os_tid', 'neutron_group_id']),
                mock.call.tags([self.context.tenant_id, 1]),
            ], any_order=True)
            connection.securityprofile.assert_any_call(self.profile_id)
            self.assertTrue(connection.securityprofile().delete)

    def test_security_group_delete_not_found(self):
        with self._stubs() as connection:
            connection.securityprofile().query().results.return_value = {
                'result_count': 0, 'results': []}
            with self.assertRaises(sg_ext.SecurityGroupNotFound):
                self.driver.delete_security_group(self.context, 1)


class TestNVPDriverUpdateSecurityGroup(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._next_connection" % self.d_pkg),
        ) as (conn, next_conn):
            connection = self._create_connection()
            connection.securityprofile = self._create_security_profile()
            conn.return_value = connection
            yield connection

    def test_security_group_update(self):
        with self._stubs() as connection:
            self.driver.update_security_group(self.context, 1, name='bar')
            connection.securityprofile.assert_any_call(self.profile_id)
            connection.securityprofile().assert_has_calls([
                mock.call.display_name('bar'),
                mock.call.update()],
                any_order=True)

    def test_security_group_update_not_found(self):
        with self._stubs() as connection:
            connection.securityprofile().query().results.return_value = {
                'result_count': 0, 'results': []}
            with self.assertRaises(sg_ext.SecurityGroupNotFound):
                self.driver.update_security_group(self.context, 1)

    def test_security_group_update_with_rules(self):
        ingress_rules = [{'ethertype': 'IPv4', 'protocol': 6},
                         {'ethertype': 'IPv6',
                          'remote_ip_prefix': '192.168.0.1'}]
        egress_rules = [{'ethertype': 'IPv4', 'protocol': 17,
                         'port_range_min': 0, 'port_range_max': 100}]
        with self._stubs() as connection:
            self.driver.update_security_group(
                self.context, 1,
                port_ingress_rules=ingress_rules,
                port_egress_rules=egress_rules)
            connection.securityprofile.assert_any_call(self.profile_id)
            connection.securityprofile().assert_has_calls([
                mock.call.port_ingress_rules(ingress_rules),
                mock.call.port_egress_rules(egress_rules),
                mock.call.update(),
            ], any_order=True)

    def test_security_group_update_rules_at_max(self):
        ingress_rules = [{'ethertype': 'IPv4', 'protocol': 6},
                         {'ethertype': 'IPv6',
                          'remote_ip_prefix': '192.168.0.1'}]
        egress_rules = [{'ethertype': 'IPv4', 'protocol': 17,
                         'port_range_min': 0, 'port_range_max': 100},
                        {'ethertype': 'IPv4', 'remote_group_id': 2}]
        with self._stubs():
            with self.assertRaises(sg_ext.nexception.InvalidInput):
                self.driver.update_security_group(
                    self.context, 1,
                    port_ingress_rules=ingress_rules,
                    port_egress_rules=egress_rules)


class TestNVPDriverCreateSecurityGroupRule(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self):
        with contextlib.nested(
            mock.patch("%s._connection" % self.d_pkg),
            mock.patch("%s._next_connection" % self.d_pkg),
        ) as (conn, next_conn):
            connection = self._create_connection()
            connection.securityprofile = self._create_security_profile()
            connection.securityrule = self._create_security_rule()
            connection.lswitch_port().query.return_value = (
                self._create_lport_query(1, [self.profile_id]))
            conn.return_value = connection
            yield connection

    def test_security_rule_create(self):
        with self._stubs() as connection:
            self.driver.create_security_group_rule(
                self.context, 1,
                {'ethertype': 'IPv4', 'direction': 'ingress'})
            connection.securityprofile.assert_any_call(self.profile_id)
            connection.securityprofile().assert_has_calls([
                mock.call.port_ingress_rules([{'ethertype': 'IPv4'}]),
                mock.call.update(),
            ], any_order=True)

    def test_security_rule_create_with_ip_prefix_and_profile(self):
        with self._stubs() as connection:
            self.driver.create_security_group_rule(
                self.context, 1,
                {'ethertype': 'IPv4', 'direction': 'ingress',
                 'remote_ip_prefix': "pre", "remote_group_id": "group",
                 "protocol": "udp"})
            connection.securityprofile.assert_any_call(self.profile_id)
            connection.securityprofile().assert_has_calls([
                mock.call.port_ingress_rules([{'ethertype': 'IPv4',
                                               "ip_prefix": "pre",
                                               "profile_uuid": "group",
                                               "protocol": "udp"}]),
                mock.call.update(),
            ], any_order=True)

    def test_security_rule_create_invalid_direction(self):
        with self._stubs():
            with self.assertRaises(AttributeError):
                self.driver.create_security_group_rule(
                    self.context, 1,
                    {'ethertype': 'IPv4', 'direction': 'instantregret'})

    def test_security_rule_create_duplicate(self):
        with self._stubs() as connection:
            connection.securityprofile().read().update({
                'logical_port_ingress_rules': [{'ethertype': 'IPv4'}],
                'logical_port_egress_rules': []})
            with self.assertRaises(sg_ext.SecurityGroupRuleExists):
                self.driver.create_security_group_rule(
                    self.context, 1,
                    {'ethertype': 'IPv4', 'direction': 'ingress'})

    def test_security_rule_create_not_found(self):
        with self._stubs() as connection:
            connection.securityprofile().query().results.return_value = {
                'result_count': 0, 'results': []}
            with self.assertRaises(sg_ext.SecurityGroupNotFound):
                self.driver.create_security_group_rule(
                    self.context, 1,
                    {'ethertype': 'IPv4', 'direction': 'egress'})

    def test_security_rule_create_over_port(self):
        with self._stubs() as connection:
            connection.securityprofile().read().update(
                {'logical_port_ingress_rules': [1, 2]})
            with self.assertRaises(sg_ext.nexception.InvalidInput):
                self.driver.create_security_group_rule(
                    self.context, 1,
                    {'ethertype': 'IPv4', 'direction': 'egress'})
            self.assertTrue(connection.lswitch_port().query.called)


class TestNVPDriverDeleteSecurityGroupRule(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, rules=[]):
        rulelist = {'logical_port_ingress_rules': [],
                    'logical_port_egress_rules': []}
        for rule in rules:
            rulelist['logical_port_%s_rules' % rule.pop('direction')].append(
                rule)
        with contextlib.nested(
                mock.patch("%s._connection" % self.d_pkg),
        ) as (conn,):
            connection = self._create_connection()
            connection.securityprofile = self._create_security_profile()
            connection.securityrule = self._create_security_rule()
            connection.securityprofile().read().update(rulelist)
            conn.return_value = connection
            yield connection

    def test_delete_security_group(self):
        with self._stubs(
            rules=[{'ethertype': 'IPv4', 'direction': 'ingress'},
                   {'ethertype': 'IPv6', 'direction': 'egress'}]
        ) as connection:
            self.driver.delete_security_group_rule(
                self.context, 1, {'ethertype': 'IPv6', 'direction': 'egress'})
            connection.securityprofile.assert_any_call(self.profile_id)
            connection.securityprofile().assert_has_calls([
                mock.call.port_egress_rules([]),
                mock.call.update(),
            ], any_order=True)

    def test_delete_security_group_does_not_exist(self):
        with self._stubs(rules=[{'ethertype': 'IPv4',
                                 'direction': 'ingress'}]):
            with self.assertRaises(sg_ext.SecurityGroupRuleNotFound):
                self.driver.delete_security_group_rule(
                    self.context, 1,
                    {'ethertype': 'IPv6', 'direction': 'egress'})


class TestNVPDriverLoadConfig(TestNVPDriver):
    def test_load_config(self):
        controllers = "192.168.221.139:443:admin:admin:30:10:2:2"
        cfg.CONF.set_override("controller_connection", [controllers], "NVP")
        self.driver.load_config()
        conn = self.driver.nvp_connections[0]
        self.assertEqual(conn["username"], "admin")
        self.assertEqual(conn["retries"], 2)
        self.assertEqual(conn["redirects"], '2')
        self.assertEqual(conn["http_timeout"], 10)
        self.assertEqual(conn["req_timeout"], "30")
        self.assertEqual(conn["default_tz"], None)
        self.assertEqual(conn["password"], "admin")
        self.assertEqual(conn["ip_address"], "192.168.221.139")
        self.assertEqual(conn["port"], "443")
        cfg.CONF.clear_override("controller_connection", "NVP")

    def test_load_config_no_connections(self):
        self.driver.load_config()
        self.assertEqual(len(self.driver.nvp_connections), 0)


class TestNVPDriverLoadConfigRandomController(TestNVPDriver):
    @mock.patch("random.randint")
    def test_load_config(self, randint):
        controllers = "192.168.221.139:443:admin:admin:30:10:2:2"
        cfg.CONF.set_override("controller_connection", [controllers], "NVP")
        cfg.CONF.set_override("random_initial_controller", True,
                              "NVP")
        randint.return_value = 0
        self.driver.load_config()
        self.assertTrue(randint.called)
        cfg.CONF.clear_override("controller_connection", "NVP")
        cfg.CONF.clear_override("random_initial_controller", "NVP")


class TestNVPGetConnection(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, has_conn):
        controllers = "192.168.221.139:443:admin:admin:30:10:2:2"
        cfg.CONF.set_override("controller_connection", [controllers], "NVP")
        if has_conn:
            self.driver.nvp_connections.append(dict(connection="foo",
                                                    usages=0))
        else:
            self.driver.nvp_connections.append(dict(port="443",
                                                    ip_address="192.168.0.1",
                                                    username="admin",
                                                    password="admin",
                                                    http_timeout=10,
                                                    retries=1,
                                                    backoff=0,
                                                    usages=0))
        with contextlib.nested(
            mock.patch("aiclib.nvp.Connection"),
            mock.patch("%s._next_connection" % self.d_pkg)
        ) as (aiclib_conn, next_conn):
            yield aiclib_conn, next_conn
        cfg.CONF.clear_override("controller_connection", "NVP")

    def test_get_connection(self):
        with self._stubs(has_conn=False) as (aiclib_conn, next_conn):
            with self.driver.get_connection():
                pass
            self.assertTrue(aiclib_conn.called)
            self.assertFalse(next_conn.called)

    def test_get_connection_connection_defined(self):
        with self._stubs(has_conn=True) as (aiclib_conn, next_conn):
            with self.driver.get_connection():
                pass
            self.assertFalse(aiclib_conn.called)
            self.assertFalse(next_conn.called)

    def test_get_connection_iterates(self):
        with self._stubs(has_conn=True) as (aiclib_conn, next_conn):
            try:
                with self.driver.get_connection():
                    raise Exception("Failure")
            except Exception:
                pass
            self.assertFalse(aiclib_conn.called)
            self.assertTrue(next_conn.called)

    def test_get_connection_with_threshold(self):
        cfg.CONF.set_override("connection_switching_threshold", 1, "NVP")
        with self._stubs(has_conn=True) as (aiclib_conn, next_conn):
            with self.driver.get_connection():
                pass

            self.assertFalse(aiclib_conn.called)
            self.assertTrue(next_conn.called)
        cfg.CONF.clear_override("connection_switching_threshold", "NVP")

    def test_get_connection_with_threshold_next_conn_not_called(self):
        cfg.CONF.set_override("connection_switching_threshold", 2, "NVP")
        with self._stubs(has_conn=True) as (aiclib_conn, next_conn):
            with self.driver.get_connection():
                pass

            self.assertFalse(aiclib_conn.called)
            self.assertFalse(next_conn.called)
        cfg.CONF.clear_override("connection_switching_threshold", "NVP")


class TestNVPGetConnectionNoneDefined(TestNVPDriver):
    def test_get_connection(self):
        with self.assertRaises(q_exc.NoBackendConnectionsDefined):
            with self.driver.get_connection():
                pass


class TestNVPNextConnection(TestNVPDriver):
    @contextlib.contextmanager
    def _stubs(self, rand=False):
        controllers = "192.168.221.139:443:admin:admin:30:10:2:2"
        cfg.CONF.set_override("controller_connection", [controllers], "NVP")
        if rand:
            cfg.CONF.set_override("connection_switching_random", True, "NVP")
        conn1 = dict(port="443", ip_address="192.168.0.1", username="admin",
                     password="admin", http_timeout=10, retries=1, backoff=0,
                     usages=0)
        conn2 = conn1.copy()
        conn2["ip_address"] = "192.168.0.2"

        self.driver.nvp_connections.extend([conn1, conn2])
        with contextlib.nested(
            mock.patch("random.randint")
        ) as (randint,):
            randint.return_value = 1
            yield randint
        cfg.CONF.clear_override("controller_connection", "NVP")
        if rand:
            cfg.CONF.clear_override("connection_switching_random", "NVP")

    def test_get_connection(self):
        with self._stubs() as randint:
            self.driver._next_connection()
            self.assertEqual(1, self.driver.conn_index)
            self.assertFalse(randint.called)

    def test_get_connection_random(self):
        with self._stubs(rand=True) as randint:
            self.driver._next_connection()
            self.assertEqual(1, self.driver.conn_index)
            self.assertTrue(randint.called)
