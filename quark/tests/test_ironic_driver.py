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

import netaddr

import json

import mock
from oslo_config import cfg

import quark.drivers.ironic_driver
from quark import network_strategy
from quark.tests import test_base


class TestIronicDriverBase(test_base.TestBase):

    def setUp(self):
        super(TestIronicDriverBase, self).setUp()

        net_strategy = {
            "1": {
                "bridge": "publicnet",
                "subnets": {"4": "1", "6": "2"}
            },
            "2": {
                "bridge": "publicnet",
                "subnets": {"3": "1", "6": "4"}
            }
        }
        strategy = json.dumps(net_strategy)
        quark.drivers.ironic_driver.STRATEGY = network_strategy.JSONStrategy(
            strategy)
        cfg.CONF.set_override("default_net_strategy", strategy,
                              "QUARK")

        cfg.CONF.set_override("operation_delay", 0,
                              "IRONIC")
        cfg.CONF.set_override("operation_backoff", 0,
                              "IRONIC")

    @contextlib.contextmanager
    def _stubs(self, create_port=None, delete_port=None):
        importer, client, create, delete = self._create_client(
            create_port, delete_port)
        driver = quark.drivers.ironic_driver.IronicDriver()
        yield driver, client, create, delete

    def _create_client(self, create_port=None, delete_port=None):
        patcher = mock.patch('quark.drivers.ironic_driver.importutils')
        importer_mock = patcher.start()
        self.addCleanup(patcher.stop)

        client_mock = mock.Mock()
        importer_mock.import_class.return_value = client_mock

        create_port_mock = client_mock.return_value.create_port
        if not create_port:
            create_port = [{"port": {"vlan_id": 500, "id": "portid"}}]
        create_port_mock.side_effect = create_port

        delete_port_mock = client_mock.return_value.delete_port
        if delete_port is None:
            delete_port = [None]
        delete_port_mock.side_effect = delete_port
        return importer_mock, client_mock, create_port_mock, delete_port_mock

    def _create_address(self, cidr, default_route=True):
        cidr = netaddr.IPNetwork(cidr)

        gateway_ip = str(netaddr.IPAddress(cidr.first + 1))
        host_ip = str(netaddr.IPAddress(cidr.first + 2))

        dns = [{"ip": "8.8.8.8"}, {"ip": "8.8.4.4"}]

        routes = [{"cidr": "earth", "gateway": gateway_ip},
                  {"cidr": "moon", "gateway": gateway_ip}]

        address = {}
        address["address_readable"] = host_ip

        subnet = {
            "id": "subnet_%s" % str(cidr),
            "name": "subnet_name",
            "tenant_id": "fake",
            "dns_nameservers": dns,
            "routes": routes if not default_route else [],
            "gateway_ip": gateway_ip if default_route else None,
            "cidr": str(cidr)
        }
        address["subnet"] = subnet
        return address

    def _create_base_net_driver(self, driver_type):
        driver = mock.Mock()
        driver.get_lswitch_ids_for_network.return_value = ["lswitch1"]
        driver.get_name.return_value = driver_type
        return driver


class TestIronicDriver(TestIronicDriverBase):

    def test_import_client_class(self):
        importer, _, _, _ = self._create_client()
        quark.drivers.ironic_driver.IronicDriver()
        importer.import_class.assert_called_once_with(
            cfg.CONF.IRONIC.ironic_client)

    def test_client_is_instantiated(self):
        with self._stubs() as (driver, client, _, _):
            params = {
                'endpoint_url': cfg.CONF.IRONIC.endpoint_url,
                'timeout': cfg.CONF.IRONIC.timeout,
                'insecure': cfg.CONF.IRONIC.insecure,
                'ca_cert': cfg.CONF.IRONIC.ca_cert,
                'auth_strategy': cfg.CONF.IRONIC.auth_strategy,
                'tenant_name': cfg.CONF.IRONIC.tenant_name,
                'tenant_id': cfg.CONF.IRONIC.tenant_id,
                'password': cfg.CONF.IRONIC.password
            }
            client.assert_called_once_with(**params)


class TestIronicDriverIPAMStrategies(TestIronicDriverBase):

    def test_ipam_strategies(self):
        with self._stubs() as (driver, client, _, _):
            self.assertEqual(
                driver._ipam_strategies,
                json.loads(cfg.CONF.IRONIC.ironic_ipam_strategies))

    def test_invalid_ipam_strategy_raises(self):
        cfg.CONF.set_override('ironic_ipam_strategies',
                              '{}',
                              'IRONIC')
        self.addCleanup(cfg.CONF.clear_override,
                        'ironic_ipam_strategies',
                        'IRONIC')
        self.assertRaises(quark.drivers.ironic_driver.IronicDriver)

    def test_ipam_strategy_provider_overrides(self):
        with self._stubs() as (driver, _, _, _):
            strategy = driver.select_ipam_strategy("1", "BOTH")
            self.assertEqual(strategy, "IRONIC_BOTH")

    def test_ipam_strategy_provider_returns_default(self):
        with self._stubs() as (driver, _, _, _):
            strategy = driver.select_ipam_strategy("1", "WTF")
            self.assertEqual(strategy, "IRONIC_ANY")

    def test_ipam_strategy_tenant_returns_network_strategy(self):
        with self._stubs() as (driver, _, _, _):
            strategy = driver.select_ipam_strategy("3", "WTF")
            self.assertEqual(strategy, "WTF")


class TestIronicDriverCreatePort(TestIronicDriverBase):

    def test_create_port(self):
        create_response = {
            "port": {
                "id": "port1",
                "vlan_id": 120
            }
        }
        with self._stubs(create_port=[create_response]) as (driver, _,
                                                            create, _):

            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "UNMANAGED")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [],
                "security_groups": [],
            }
            res = driver.create_port(
                self.context, network_id, port_id,
                **kwargs)

            expected_call = {
                'port': {
                    'switch:hardware_id': kwargs["instance_node_id"],
                    'device_owner': '',
                    'network_type': "UNMANAGED",
                    'mac_address': '00:00:00:00:00:01',
                    'network_id': network_id,
                    'tenant_id': self.context.tenant_id,
                    'roles': self.context.roles,
                    'dynamic_network': True,
                    'fixed_ips': [],
                    'id': port_id,
                    'device_id': kwargs["device_id"]
                }
            }

            self.assertEqual(
                res, {"uuid": create_response["port"]["id"],
                      "vlan_id": create_response["port"]["vlan_id"]})
            create.assert_called_once_with(body=expected_call)

    def test_create_port_includes_lswitch_ids(self):
        create_response = {
            "port": {
                "id": "port1",
                "vlan_id": 120
            }
        }
        with self._stubs(create_port=[create_response]) as (driver, _,
                                                            create, _):

            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "NVP")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [],
                "security_groups": [],
            }
            res = driver.create_port(
                self.context, network_id, port_id,
                **kwargs)

            expected_call = {
                'port': {
                    'switch:hardware_id': kwargs["instance_node_id"],
                    'device_owner': '',
                    'network_type': "NVP",
                    'mac_address': '00:00:00:00:00:01',
                    'network_id': network_id,
                    'tenant_id': self.context.tenant_id,
                    'roles': self.context.roles,
                    'lswitch_id': 'lswitch1',
                    'dynamic_network': True,
                    'fixed_ips': [],
                    'id': port_id,
                    'device_id': kwargs["device_id"]
                }
            }

            self.assertEqual(
                res, {"uuid": create_response["port"]["id"],
                      "vlan_id": create_response["port"]["vlan_id"]})
            create.assert_called_once_with(body=expected_call)

    def test_create_port_includes_roles(self):
        create_response = {
            "port": {
                "id": "port1",
                "vlan_id": 120
            }
        }
        with self._stubs(create_port=[create_response]) as (driver, _,
                                                            create, _):

            self.context.roles = ["role1", "role2"]
            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "NVP")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [],
                "security_groups": [],
            }
            res = driver.create_port(
                self.context, network_id, port_id,
                **kwargs)

            expected_call = {
                'port': {
                    'switch:hardware_id': kwargs["instance_node_id"],
                    'device_owner': '',
                    'network_type': "NVP",
                    'mac_address': '00:00:00:00:00:01',
                    'network_id': network_id,
                    'tenant_id': self.context.tenant_id,
                    'roles': ["role1", "role2"],
                    'lswitch_id': 'lswitch1',
                    'dynamic_network': True,
                    'fixed_ips': [],
                    'id': port_id,
                    'device_id': kwargs["device_id"]
                }
            }

            self.assertEqual(
                res, {"uuid": create_response["port"]["id"],
                      "vlan_id": create_response["port"]["vlan_id"]})
            create.assert_called_once_with(body=expected_call)

    def test_create_port_retries(self):
        create_response = [
            Exception("uhoh"),
            {"port": {"id": "port1", "vlan_id": 120}}
        ]
        with self._stubs(create_port=create_response) as (driver, _,
                                                          create, _):

            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "UNMANAGED")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [],
                "security_groups": [],
            }
            res = driver.create_port(
                self.context, network_id, port_id,
                **kwargs)

            expected_call = {
                'port': {
                    'switch:hardware_id': kwargs["instance_node_id"],
                    'device_owner': '',
                    'network_type': "UNMANAGED",
                    'mac_address': '00:00:00:00:00:01',
                    'network_id': network_id,
                    'tenant_id': self.context.tenant_id,
                    'roles': self.context.roles,
                    'dynamic_network': True,
                    'fixed_ips': [],
                    'id': port_id,
                    'device_id': kwargs["device_id"]
                }
            }

            self.assertEqual(
                res,
                {"uuid": create_response[1]["port"]["id"],
                 "vlan_id": create_response[1]["port"]["vlan_id"]})

            self.assertEqual(
                create.call_args_list,
                [mock.call(body=expected_call),
                 mock.call(body=expected_call)])

    def test_create_port_raises_after_retry_failures(self):
        create_response = [
            Exception("uhoh"),
            Exception("uhoh"),
            Exception("uhoh"),
        ]
        with self._stubs(create_port=create_response) as (driver, _,
                                                          create, _):

            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "UNMANAGED")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [],
                "security_groups": [],
            }
            self.assertRaises(
                quark.drivers.ironic_driver.IronicException,
                driver.create_port,
                self.context, network_id, port_id, **kwargs)

            expected_call = {
                'port': {
                    'switch:hardware_id': kwargs["instance_node_id"],
                    'device_owner': '',
                    'network_type': "UNMANAGED",
                    'mac_address': '00:00:00:00:00:01',
                    'network_id': network_id,
                    'tenant_id': self.context.tenant_id,
                    'roles': self.context.roles,
                    'dynamic_network': True,
                    'fixed_ips': [],
                    'id': port_id,
                    'device_id': kwargs["device_id"]
                }
            }

            self.assertEqual(create.call_count, 3)

            self.assertEqual(
                create.call_args_list,
                [mock.call(body=expected_call),
                 mock.call(body=expected_call),
                 mock.call(body=expected_call)])

    def test_create_port_raises_with_missing_required_kwargs(self):
        with self._stubs() as (driver, _, create, _):

            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "UNMANAGED")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [],
                "security_groups": [],
            }

            for kwarg in ["base_net_driver", "device_id",
                          "instance_node_id", "mac_address"]:

                val = kwargs.pop(kwarg)

                self.assertRaises(
                    quark.drivers.ironic_driver.IronicException,
                    driver.create_port,
                    self.context, network_id, port_id, **kwargs)

                kwargs[kwarg] = val

                create.assert_not_called()

    def test_create_port_raises_with_security_groups(self):
        with self._stubs() as (driver, _, create, _):

            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "UNMANAGED")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [],
                "security_groups": ["foo"],
            }

            self.assertRaises(
                quark.drivers.ironic_driver.IronicException,
                driver.create_port,
                self.context, network_id, port_id, **kwargs)

            create.assert_not_called()

    def test_create_port_with_fixed_ips(self):
        create_response = {
            "port": {
                "id": "port1",
                "vlan_id": 120
            }
        }
        with self._stubs(create_port=[create_response]) as (driver, _,
                                                            create, _):

            network_id = "net1"
            port_id = "port1"

            # mock of the default driver class for the network
            base_net_driver = self._create_base_net_driver(
                "UNMANAGED")

            kwargs = {
                "device_id": "device1",
                "instance_node_id": "nodeid1",
                "mac_address": {"address": 1},
                "base_net_driver": base_net_driver,
                "addresses": [self._create_address("10.0.0.0/30"),
                              self._create_address("10.0.0.5/30",
                                                   default_route=False)],
                "security_groups": [],
            }
            res = driver.create_port(
                self.context, network_id, port_id,
                **kwargs)

            fixed_ips = [
                {'subnet': {
                    'name': 'subnet_name',
                    'tenant_id': 'fake',
                    'dns_nameservers': ['8.8.8.8', '8.8.4.4'],
                    'host_routes': [],
                    'gateway_ip': '10.0.0.1',
                    'cidr': '10.0.0.0/30',
                    'id': 'subnet_10.0.0.0/30'},
                 'ip_address': '10.0.0.2'},
                {'subnet': {
                    'name': 'subnet_name',
                    'tenant_id': 'fake',
                    'dns_nameservers': ['8.8.8.8', '8.8.4.4'],
                    'host_routes': [
                        {'nexthop': '10.0.0.5',
                         'destination': 'earth'},
                        {'nexthop': '10.0.0.5',
                         'destination': 'moon'}
                    ],
                    'gateway_ip': None,
                    'cidr': '10.0.0.5/30',
                    'id': 'subnet_10.0.0.5/30'},
                 'ip_address': '10.0.0.6'}
            ]

            expected_call = {
                'port': {
                    'switch:hardware_id': kwargs["instance_node_id"],
                    'device_owner': '',
                    'network_type': "UNMANAGED",
                    'mac_address': '00:00:00:00:00:01',
                    'network_id': network_id,
                    'tenant_id': self.context.tenant_id,
                    'roles': self.context.roles,
                    'dynamic_network': True,
                    'fixed_ips': fixed_ips,
                    'id': port_id,
                    'device_id': kwargs["device_id"]
                }
            }

            self.assertEqual(
                res, {"uuid": create_response["port"]["id"],
                      "vlan_id": create_response["port"]["vlan_id"]})
            create.assert_called_once_with(body=expected_call)


class TestIronicDriverDeletePort(TestIronicDriverBase):

    def test_delete_port(self):
        with self._stubs(delete_port=[None]) as (driver, client,
                                                 _, delete):
            driver.delete_port(self.context, "foo")
            delete.assert_called_once_with("foo")

    def test_delete_port_retries(self):
        delete_port = [Exception("uhoh"), None]
        with self._stubs(delete_port=delete_port) as (driver,
                                                      client, _,
                                                      delete):
            driver.delete_port(self.context, "foo")
            self.assertEqual(delete.call_count, 2)
            self.assertEqual(
                delete.call_args_list,
                [mock.call("foo"), mock.call("foo")])

    def test_delete_port_fail_does_not_raise(self):
        delete_port = [Exception("uhoh"),
                       Exception("uhoh"),
                       Exception("uhoh")]
        with self._stubs(delete_port=delete_port) as (driver,
                                                      client, _,
                                                      delete):
            driver.delete_port(self.context, "foo")
            self.assertEqual(delete.call_count, 3)
            self.assertEqual(
                delete.call_args_list,
                [mock.call("foo"), mock.call("foo"),
                 mock.call("foo")])

    def test_delete_port_ignores_404(self):
        delete_port = [Exception("404 not found"), None]
        with self._stubs(delete_port=delete_port) as (driver,
                                                      client, _,
                                                      delete):
            driver.delete_port(self.context, "foo")
            delete.assert_called_once_with("foo")


class TestIronicDriverUpdatePort(TestIronicDriverBase):

    def test_update_does_nothing(self):
        with self._stubs() as (driver, client,
                               _, delete):
            res = driver.update_port(self.context, "foo", **{})
            client.update_port.assert_not_called()
            self.assertEqual(res, {"uuid": "foo"})

    def test_update_with_sg_raises(self):
        with self._stubs() as (driver, client,
                               _, delete):
            self.assertRaises(
                quark.drivers.ironic_driver.IronicException,
                driver.update_port,
                self.context, "foo",
                security_groups=["sg1"])


class TestIronicDriverNetwork(TestIronicDriverBase):

    def test_create_network_raises(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.create_network,
                1)

    def test_delete_network_raises(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.delete_network,
                1)

    def test_diag_network_raises(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.diag_network,
                1)


class TestIronicDriverSecurityGroups(TestIronicDriverBase):

    def test_create_security_group(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.create_security_group,
                self.context, "fake")

    def test_delete_security_group(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.delete_security_group,
                self.context, "fake")

    def test_update_security_group(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.update_security_group,
                self.context, "fake")

    def test_create_security_group_rule(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.create_security_group_rule,
                self.context, "fake", "fake_rule")

    def test_delete_security_group_rule(self):
        with self._stubs() as (driver, _, _, _):
            self.assertRaises(
                NotImplementedError,
                driver.delete_security_group_rule,
                self.context, "fake", "fake_rule")
