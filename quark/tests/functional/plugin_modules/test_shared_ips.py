# Copyright 2014 Rackspace Hosting Inc.
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
# License for# the specific language governing permissions and limitations
#  under the License.

import mock
import netaddr

import contextlib

from neutron_lib import exceptions as n_exc
from quark.db import ip_types

from quark.db import api as db_api
from quark import exceptions as q_exc
import quark.ipam
import quark.plugin
import quark.plugin_modules.ip_addresses as ip_api
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkSharedIPs(BaseFunctionalTest):
    def __init__(self, *args, **kwargs):
        super(QuarkSharedIPs, self).__init__(*args, **kwargs)
        self.disassociate_exception = q_exc.PortRequiresDisassociation
        self.cidr = "192.168.2.0/24"
        self.ip_network = netaddr.IPNetwork(self.cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        self.network = {"network": network}
        subnet = dict(ip_version=4, next_auto_assign_ip=2,
                      cidr=self.cidr, first_ip=self.ip_network.first,
                      last_ip=self.ip_network.last, ip_policy=None,
                      tenant_id="fake")
        self.subnet = {"subnet": subnet}
        port1 = {'port': dict(device_id='a')}
        port2 = {'port': dict(device_id='b')}
        port3 = {'port': dict(device_id='c')}
        port4 = {'port': dict(device_id='d')}
        self.ports_info2 = [port1, port2]
        self.ports_info4 = [port1, port2, port3, port4]

    def setUp(self):
        super(QuarkSharedIPs, self).setUp()

    def tearDown(self):
        super(QuarkSharedIPs, self).tearDown()

    def _make_port_body(self, service):
        body = dict(service=service)
        port_info = {"port": dict(body)}
        return port_info

    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_info, ports_info):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(
                mock.patch("neutron.common.rpc.get_notifier"),
                mock.patch("neutron.quota.QUOTAS.limit_check")):
            net = network_api.create_network(self.context, network_info)
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            self.context.is_admin = True
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False
            subnet_info['subnet']['network_id'] = net['id']
            sub = subnet_api.create_subnet(self.context, subnet_info)
            ports = []
            for port_info in ports_info:
                port_info['port']['network_id'] = net['id']
                ports.append(port_api.create_port(self.context, port_info))
            yield net, sub, ports

    def test_delete_ip_with_shared_owner_error(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            p_id = ports[0]['id']
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'], p_id,
                           self._make_port_body('derp'))

            with self.assertRaises(self.disassociate_exception):
                ip_api.delete_ip_address(self.context, ip['id'])

    def test_update_shared_ip_with_plural_will_error(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])
            port_ids = [ports[0]['id'], ports[3]['id']]
            shared_ip = {'ip_addresses': dict(port_ids=port_ids)}

            with self.assertRaises(n_exc.BadRequest):
                ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_update_shared_ip_with_empty_port_id_list_will_error(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])
            port_ids = []
            shared_ip = {'ip_addresses': dict(port_ids=port_ids)}

            with self.assertRaises(n_exc.BadRequest):
                ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_update_shared_ip_with_garbage_will_error(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])
            port_ids = [ports[0]['id'], ports[3]['id']]
            shared_ip = {'delasdfkj': dict(port_ids=port_ids)}

            with self.assertRaises(n_exc.BadRequest):
                ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_update_shared_ip_with_unowned_ports_is_okay(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])
            port_ids = [ports[0]['id'], ports[3]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids)}

            ip = ip_api.update_ip_address(self.context, ip['id'], shared_ip)

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))
            for port in ports_ip:
                self.assertTrue(port['id'] in port_ids)

    def test_has_shared_owner_detection(self):
        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            p_id = ports[0]['id']

            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])
            ip_db = db_api.ip_address_find(self.context, id=ip['id'],
                                           scope=db_api.ONE)
            self.assertFalse(ip_db.has_any_shared_owner())

            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'], p_id,
                           self._make_port_body('derp'))

            self.assertTrue(ip_db.has_any_shared_owner())

    def test_update_shared_ip_with_owned_port_no_error_if_present(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            p_id = ports[0]['id']

            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'], p_id,
                           self._make_port_body('derp'))

            port_ids = [ports[0]['id'], ports[2]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids)}

            ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_update_shared_ip_with_owned_port_no_error_if_present_alone(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            p_id = ports[0]['id']

            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'], p_id,
                           self._make_port_body('derp'))

            port_ids = [ports[0]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids)}

            ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_update_shared_ip_with_owned_port_no_error_if_adding(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            p_id = ports[0]['id']

            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'], p_id,
                           self._make_port_body('derp'))
            port_ids = [ports[0]['id'], ports[1]['id'], ports[2]['id']]

            shared_ip = {'ip_address': dict(port_ids=port_ids)}

            ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_update_shared_ip_with_owned_port_no_error_if_same_list(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            p_id = ports[0]['id']

            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'], p_id,
                           self._make_port_body('derp'))

            shared_ip = {'ip_address': dict(port_ids=port_ids)}

            ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_update_shared_ip_with_owned_port_error(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            p_id = ports[0]['id']

            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'], p_id,
                           self._make_port_body('derp'))

            port_ids = [ports[2]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids)}

            with self.assertRaises(self.disassociate_exception):
                ip_api.update_ip_address(self.context, ip['id'], shared_ip)

    def test_create_shared_ips_with_port_ids(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

    def test_create_shared_ips_fails_with_plural_body(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_addresses': dict(port_ids=port_ids,
                                              network_id=net['id'],
                                              version=4)}
            with self.assertRaises(n_exc.BadRequest):
                ip_api.create_ip_address(self.context, shared_ip)

    def test_create_shared_ips_fails_with_garbage_body(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'derpie_derp': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}
            with self.assertRaises(n_exc.BadRequest):
                ip_api.create_ip_address(self.context, shared_ip)

    def test_shared_ip_in_fixed_ip_list(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            for port in ports:
                self.assertEqual(1, len(port['fixed_ips']))

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            p_id = ports[0]['id']

            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

            port_ip_update = ip_api.update_port_for_ip_address
            updated_port = port_ip_update(self.context, ip['id'],
                                          p_id, self._make_port_body('derp'))
            self.assertEqual('derp', updated_port.get('service'))

            port = port_api.get_port(self.context, p_id)
            self.assertEqual(2, len(port['fixed_ips']))

    def test_ip_port_list_has_services(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            for port in ports:
                self.assertEqual(1, len(port['fixed_ips']))

            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'],
                           ports[0]['id'], self._make_port_body('derp'))

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

            for port in ports_ip:
                self.assertTrue('service' in port)
                self.assertTrue('device_id' in port)
                self.assertTrue('id' in port)
                self.assertTrue(port['service'] in ('derp', 'none'),
                                'Service is: %s' % str(port['service']))

    def test_can_delete_ip_without_active_port(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):
            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            ip_api.delete_ip_address(self.context, ip['id'])
            with self.assertRaises(q_exc.IpAddressNotFound):
                ip_api.get_ip_address(self.context, ip['id'])

    def test_cannot_delete_ip_with_active_port(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):
            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            port_ip_update = ip_api.update_port_for_ip_address
            port_ip_update(self.context, ip['id'],
                           ports[0]['id'], self._make_port_body('derp'))

            with self.assertRaises(self.disassociate_exception):
                ip_api.delete_ip_address(self.context, ip['id'])


class QuarkSharedIPsQuotaCheck(BaseFunctionalTest):
    def __init__(self, *args, **kwargs):
        super(QuarkSharedIPsQuotaCheck, self).__init__(*args, **kwargs)
        self.disassociate_exception = q_exc.PortRequiresDisassociation
        self.cidr = "192.168.2.0/24"
        self.ip_network = netaddr.IPNetwork(self.cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        self.network = {"network": network}
        subnet = dict(ip_version=4, next_auto_assign_ip=2,
                      cidr=self.cidr, first_ip=self.ip_network.first,
                      last_ip=self.ip_network.last, ip_policy=None,
                      tenant_id="fake")
        self.subnet = {"subnet": subnet}
        port1 = {'port': dict(device_id='a')}
        port2 = {'port': dict(device_id='b')}
        port3 = {'port': dict(device_id='c')}
        port4 = {'port': dict(device_id='d')}
        self.ports_info2 = [port1, port2]
        self.ports_info4 = [port1, port2, port3, port4]

    def setUp(self):
        super(QuarkSharedIPsQuotaCheck, self).setUp()

    def tearDown(self):
        super(QuarkSharedIPsQuotaCheck, self).tearDown()

    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_info, ports_info):
        self.ipam = quark.ipam.QuarkIpamANY()
        with contextlib.nested(
                mock.patch("neutron.common.rpc.get_notifier")):
            self.context.is_admin = True
            net = network_api.create_network(self.context, network_info)
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            macrng_api.create_mac_address_range(self.context, mac)
            self.context.is_admin = False
            subnet_info['subnet']['network_id'] = net['id']
            sub = subnet_api.create_subnet(self.context, subnet_info)
            ports = []
            for port_info in ports_info:
                port_info['port']['network_id'] = net['id']
                ports.append(port_api.create_port(self.context, port_info))
            yield net, sub, ports

    def test_create_shared_ip_over_public_network_quota(self):
        network = dict(name="public", tenant_id="fake", network_plugin="BASE",
                       id='00000000-0000-0000-0000-000000000000')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            port_ids = [ports[2]['id'], ports[3]['id']]
            shared_ip2 = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE(roaet): this is hardcoded to 5 and will fail after 5
            for i in xrange(5):
                # NOTE(roaet): need to do this modulo stuff to not hit IP quota
                if i % 2 == 0:
                    ip_api.create_ip_address(self.context, shared_ip)
                else:
                    ip_api.create_ip_address(self.context, shared_ip2)

            with self.assertRaises(q_exc.CannotCreateMoreSharedIPs):
                ip_api.create_ip_address(self.context, shared_ip)

    def test_create_shared_ip_over_isolated_network_quota(self):
        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            port_ids = [ports[2]['id'], ports[3]['id']]
            shared_ip2 = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE(roaet): this is hardcoded to 5
            for i in xrange(4):
                # NOTE(roaet): need to do this modulo stuff to not hit IP quota
                if i % 2 == 0:
                    ip_api.create_ip_address(self.context, shared_ip)
                else:
                    ip_api.create_ip_address(self.context, shared_ip2)

            # NOTE(roaet): this should not fail
            ip_api.create_ip_address(self.context, shared_ip)

    def test_create_shared_ip_over_service_network_quota(self):
        network = dict(name="service", tenant_id="fake", network_plugin="BASE",
                       id='11111111-1111-1111-1111-111111111111')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}

            # NOTE(roaet): this is hardcoded to 0 so should fail instantly
            with self.assertRaises(q_exc.CannotCreateMoreSharedIPs):
                ip_api.create_ip_address(self.context, shared_ip)

    def test_create_shared_ip_over_public_total_ip_on_port_quota(self):
        network = dict(name="public", tenant_id="fake", network_plugin="BASE",
                       id='00000000-0000-0000-0000-000000000000')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            # NOTE(roaet): this is hardcoded to 6 so should fail after 5
            # since a port comes with 1 IP already
            for i in xrange(5):
                ip_api.create_ip_address(self.context, shared_ip)

            with self.assertRaises(n_exc.OverQuota):
                ip_api.create_ip_address(self.context, shared_ip)

    def test_create_shared_ip_over_isolated_total_ip_on_port_quota(self):
        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            # NOTE(roaet): this is hardcoded to 5 should fail after 4
            # since a port comes with 1 IP already
            for i in xrange(4):
                ip_api.create_ip_address(self.context, shared_ip)

            with self.assertRaises(n_exc.OverQuota):
                ip_api.create_ip_address(self.context, shared_ip)

    def test_create_shared_ip_over_service_total_ip_on_port_quota(self):
        network = dict(name="service", tenant_id="fake", network_plugin="BASE",
                       id='11111111-1111-1111-1111-111111111111')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports_info2) as (
                net, sub, ports):

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            # NOTE(roaet): this is hardcoded to 1 so should fail immediately
            with self.assertRaises(n_exc.OverQuota):
                ip_api.create_ip_address(self.context, shared_ip)
