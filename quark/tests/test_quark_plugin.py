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
    # POST /ip_address
    #    version (optional)
    #    ip_address optional
    #    network_id and device_id (or port_id)

    # 7. Create IP Address with version specified (version == 6),
    # success with ipv6 address
    # 8. Create IP Address with version specified (version == 10), failure
    # 9. Create IP Address with specifc ip_address, ip doesn't exist already,
    # associates success
    # 10. Create IP Address with specific ip_address, ip does exist already,
    # associates success
    # 11. Create IP Address with specific ip_address,
    # fail when subnet doesn't exist

    # POST /ip_address/id/ports: <== pass in a list of port_id's

    # 1. Fail: IP Address id doesn't exist
    # 2. Fail: port_id in port_ids doesn't exist
    # 3. Success: Associate ipaddress at specific id with port

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
        self.assertEqual(response['port_id'], port_id)
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_failure_1b(self):
        '''1b. Create IP address with invalid network_id and invalid
        device_id.'''
        with self.assertRaises(exceptions.IpAddressGenerationFailure):
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
        self.assertEqual(response['port_id'], port_id)
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_create_ip_address_failure_2b(self):
        '''2b. Create IP Address with invalid port_id.'''
        with self.assertRaises(exceptions.IpAddressGenerationFailure):
            ip_address = {'ip_address': {'port_id': 'fake'}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_failure_3(self):
        '''3. Create IP address with none of network_id, device_id, port_id.'''
        with self.assertRaises(exceptions.IpAddressGenerationFailure):
            ip_address = {'ip_address': {}}
            response = self.plugin.create_ip_address(self.context,
                                                     ip_address)

    def test_create_ip_address_failure_4(self):
        '''4. Create IP address with network_id and without device_id.'''
        network_id = self._create_network()['id']
        with self.assertRaises(exceptions.IpAddressGenerationFailure):
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

        with self.assertRaises(exceptions.IpAddressGenerationFailure):
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
        self.assertEqual(response['port_id'], port_id)
        self.assertEqual(response['subnet_id'], subnet['id'])

    def test_get_ip_address_success(self):
        pass

    def test_get_ip_address_failure(self):
        pass

    def test_get_ip_addresses_success(self):
        pass

    def test_update_ip_address_success(self):
        pass
