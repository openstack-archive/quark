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

import netaddr

from oslo.config import cfg
from quantum import context
from quantum.common import exceptions
from quantum.db import api as db_api

import quark.plugin

import test_base


class TestQuarkPlugin(test_base.TestBase):
    def setUp(self):
        cfg.CONF.set_override('sql_connection', 'sqlite://', 'DATABASE')
        db_api.configure_db()
        self.context = context.get_admin_context()
        self.plugin = quark.plugin.Plugin()

    def _create_network(self, name='test'):
        network = {'network': {'name': name}}
        return self.plugin.create_network(self.context, network)

    def _create_subnet(self, network_id, cidr='192.168.10.1/24'):
        subnet = {'subnet': {'cidr': cidr,
                             'network_id': network_id}}
        return self.plugin.create_subnet(self.context, subnet)

    def _create_mac_address_range(self, cidr='01:23:45/24'):
        mac_range = {'mac_address_range': {'cidr': cidr}}
        return self.plugin.create_mac_address_range(self.context, mac_range)

    def _create_port(self, network_id, device_id=''):
        port = {'port': {'network_id': network_id,
                         'device_id': device_id}}
        return self.plugin.create_port(self.context, port)

    def tearDown(self):
        db_api.clear_db()


class TestSubnets(TestQuarkPlugin):
    def test_allocated_ips_only(self):
        network_id = self._create_network()['id']
        self._create_subnet(network_id)
        self._create_mac_address_range()

        port = self._create_port(network_id)
        self.assertTrue(len(port['fixed_ips']) >= 1)

        self.plugin.delete_port(self.context, port['id'])

        # TODO(jkoelker) once the ip_addresses controller is in the api
        #                grab the fixed_ip from that and make sure it has
        #                no ports


class TestIpAddresses(TestQuarkPlugin):
    def test_create_ip_address_success_1(self):
        '''1. Create IP address with network id and device id.'''
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)
        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id)

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_failure_1b(self):
        '''1b. Create IP address with invalid network_id and invalid
        device_id.'''
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'network_id': 'fake',
                                         'device_id': 'fake'}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_success_2(self):
        '''2. Create IP address with port_id.'''
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)['id']
        self._create_mac_address_range()
        port_id = self._create_port(network_id)['id']

        ip_address = {'ip_address': {'port_id': port_id}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_failure_2b(self):
        '''2b. Create IP Address with invalid port_id.'''
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'port_id': 'fake'}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_failure_3(self):
        '''3. Create IP address with none of network_id, device_id, port_id.'''
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_failure_4(self):
        '''4. Create IP address with network_id and without device_id.'''
        network_id = self._create_network()['id']
        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'network_id': network_id}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_failure_5(self):
        '''5. Create IP Address without network_id and with device_id.'''
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)['id']
        self._create_mac_address_range()
        device_id = 'onetwothree'
        port_id = self._create_port(network_id, device_id=device_id)['id']

        with self.assertRaises(exceptions.PortNotFound):
            ip_address = {'ip_address': {'device_id': device_id}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_success_6(self):
        '''6. Create IP Address with version (v4) specified.'''
        network_id = self._create_network()['id']
        subnet_v4 = self._create_subnet(network_id, cidr='192.168.10.1/24')

        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id)

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id,
                                     'version': 4}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet_v4['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_success_7(self):
        '''7. Create IP address with version (v6) specified.'''
        # NOTE(amir): current INET custom_types not working with IPv6
        network_id = self._create_network()['id']
        subnet_v6 = self._create_subnet(network_id, cidr='fc00::/7')

        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id)

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id,
                                     'version': 6}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertIn(netaddr.IPAddress(response['address']),
                      netaddr.IPNetwork(subnet_v6['cidr']))
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_failure_8(self):
        '''8. Create IP Address with version (10) specified.'''
        network_id = self._create_network()['id']
        self._create_subnet(network_id)
        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id)

        with self.assertRaises(exceptions.IpAddressGenerationFailure):
            ip_address = {'ip_address': {'network_id': network_id,
                                         'device_id': device_id,
                                         'version': 10}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_success_9(self):
        '''9. Create IP address with specific ip_address and ip_address doesn't
        exist already.'''
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)['id']
        self._create_mac_address_range()
        port_id = self._create_port(network_id)['id']

        magic_ip = '192.168.10.123'
        ip_address = {'ip_address': {'port_id': port_id,
                                     'ip_address': magic_ip}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertEqual(response['address'], magic_ip)
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_success_10(self):
        '''10. Create IP address with specific ip_address when ip_address does
        exist already. Associates to new port successfully.'''
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)['id']
        self._create_mac_address_range()
        port = self._create_port(network_id)

        magic_ip = port['fixed_ips'][0]
        ip_address = {'ip_address': {'port_id': port['id'],
                                     'ip_address': magic_ip}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        self.assertIsNotNone(response['id'])
        self.assertEqual(response['network_id'], network_id)
        self.assertEqual(response['address'], magic_ip)
        self.assertEqual(response['port_ids'], [port_id])
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_get_ip_address_success(self):
        pass

    def test_get_ip_address_failure(self):
        pass

    def test_get_ip_addresses_success(self):
        pass

    def test_update_ip_address_failure_1(self):
        '''1. Update IP address when specific ip_address id doesn't exist.'''
        with self.assertRaises(exceptions.NotFound):
            self.plugin.update_ip_address(self.context,
                                          'no_ip_address_id',
                                          {'ip_address': {'port_ids': []}})

    def test_update_ip_address_failure_2(self):
        '''2. Update IP address when specific port_id in port_ids doesn't
        exist.'''
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)
        self._create_mac_address_range()
        device_id = 'onetwothree'
        self._create_port(network_id, device_id)

        ip_address = {'ip_address': {'network_id': network_id,
                                     'device_id': device_id}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)

        with self.assertRaises(exceptions.NotFound):
            ip_address = {'ip_address': {'port_ids': ['fake']}}
            self.plugin.update_ip_address(self.context,
                                          response['id'],
                                          ip_address)

    def test_update_ip_address_success_3(self):
        '''3. Update IP address to associate with specific port_ids.'''
        network_id = self._create_network()['id']
        subnet = self._create_subnet(network_id)
        self._create_mac_address_range()
        port = self._create_port(network_id, device_id='abc')
        port_2 = self._create_port(network_id, device_id='def')

        ip_address = {'ip_address': {'port_id': port['id']}}
        response = self.plugin.create_ip_address(self.context,
                                                 ip_address)
        ip_address = {'ip_address': {'port_ids': [port_2['id']]}}
        response = self.plugin.update_ip_address(self.context,
                                                 response['id'],
                                                 ip_address)
        self.assertEqual(response['port_ids'], [port_2['id']])
