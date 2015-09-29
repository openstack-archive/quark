import mock
import netaddr

import contextlib

from quark.db import api as db_api
from quark.db import ip_types
import quark.ipam
import quark.plugin
import quark.plugin_modules.ip_addresses as ip_api
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest


class QuarkSharedIPs(MySqlBaseFunctionalTest):
    def __init__(self, *args, **kwargs):
        super(QuarkSharedIPs, self).__init__(*args, **kwargs)
        self.cidr = "192.168.2.0/24"
        self.ip_network = netaddr.IPNetwork(self.cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        self.network = {"network": network}
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
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

    def test_create_shared_ips_with_port_ids(self):

        def _make_body(ip):
            fix_ip = dict(ip_address=ip, subnet_id=sub['id'])
            port_info = {"port": dict(fixed_ips=[fix_ip])}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):
            for p in ports:
                port_db = db_api.port_find(self.context, id=p['id'],
                                           scope=db_api.ONE)
                assocs = db_api.ip_port_association_find(self.context,
                                                         scope=db_api.ALL,
                                                         port_id=p['id'])
                self.assertEqual(1, len(p.get('fixed_ips')))
                self.assertEqual(1, len(port_db.ip_addresses))
                ip_db = port_db.ip_addresses[0]
                self.assertEqual('none', ip_db.get_service_for_port(port_db))
                self.assertEqual(1, len(assocs))

            port_ids = [ports[0]['id'], ports[1]['id']]
            shared_ip = {'ip_address': dict(port_ids=port_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

    def test_shared_ip_in_fixed_ip_list(self):

        def _make_body(service):
            body = dict(service=service)
            port_info = {"port": dict(body)}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):
            for p in ports:
                port_db = db_api.port_find(self.context, id=p['id'],
                                           scope=db_api.ONE)
                assocs = db_api.ip_port_association_find(self.context,
                                                         scope=db_api.ALL,
                                                         port_id=p['id'])
                self.assertEqual(1, len(p.get('fixed_ips')))
                self.assertEqual(1, len(port_db.ip_addresses))
                ip_db = port_db.ip_addresses[0]
                self.assertEqual('none', ip_db.get_service_for_port(port_db))
                self.assertEqual(1, len(assocs))

            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

            port = port_api.get_port(self.context, ports[0]['id'])
            self.assertEqual(2, len(port['fixed_ips']))

            port_ip_update = ip_api.update_port_for_ip_address
            updated_port = port_ip_update(self.context, ip['id'],
                                          ports[0]['id'], _make_body('derp'))
            self.assertEqual('derp', updated_port.get('service'))

            port = ip_api.get_port_for_ip_address(self.context, ip['id'],
                                                  ports[0]['id'])
            self.assertEqual('derp', port.get('service'))
            port = ip_api.get_port_for_ip_address(self.context, ip['id'],
                                                  ports[1]['id'])
            self.assertEqual('none', port.get('service'))

    def test_create_shared_ips_with_device_ids(self):

        with self._stubs(self.network, self.subnet, self.ports_info2) as (
                net, sub, ports):
            for p in ports:
                port_db = db_api.port_find(self.context, id=p['id'],
                                           scope=db_api.ONE)
                assocs = db_api.ip_port_association_find(self.context,
                                                         scope=db_api.ALL,
                                                         port_id=p['id'])
                self.assertEqual(1, len(p.get('fixed_ips')))
                self.assertEqual(1, len(port_db.ip_addresses))
                ip_db = port_db.ip_addresses[0]
                self.assertEqual('none', ip_db.get_service_for_port(port_db))
                self.assertEqual(1, len(assocs))

            device_ids = [ports[0]['device_id'], ports[1]['device_id']]
            shared_ip = {'ip_address': dict(device_ids=device_ids,
                                            network_id=net['id'],
                                            version=4)}
            ip = ip_api.create_ip_address(self.context, shared_ip)
            self.assertEqual(ip_types.SHARED, ip['type'])

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip['id'])
            self.assertEqual(2, len(ports_ip))

    def test_filter_ip_by_device_and_service(self):

        def _make_body(service):
            body = dict(service=service)
            port_info = {"port": dict(body)}
            return port_info

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):
            port_ids1 = [ports[0]['id'], ports[1]['id']]
            port_ids2 = [ports[2]['id'], ports[3]['id']]

            filters = dict(device_id='a')
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(1, len(ips))

            shared_ip1 = {'ip_address': dict(port_ids=port_ids1,
                                             network_id=net['id'],
                                             version=4)}
            ip1 = ip_api.create_ip_address(self.context, shared_ip1)
            self.assertEqual(2, len(ip1['port_ids']))

            shared_ip2 = {'ip_address': dict(port_ids=port_ids2,
                                             network_id=net['id'],
                                             version=4)}
            ip2 = ip_api.create_ip_address(self.context, shared_ip2)
            self.assertEqual(2, len(ip2['port_ids']))

            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip1['id'])
            self.assertEqual(2, len(ports_ip))
            ports_ip = ip_api.get_ports_for_ip_address(self.context, ip2['id'])
            self.assertEqual(2, len(ports_ip))

            filters = dict(device_id='a')
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(2, len(ips))

            filters = dict(device_id='x')
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(0, len(ips))

            filters = dict(device_id='a', service='derp')
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(0, len(ips))

            filters = dict(service='derp')
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(0, len(ips))

            filters = dict(device_id='a', service='none')
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(2, len(ips))

            port_ip_update = ip_api.update_port_for_ip_address
            updated_port = port_ip_update(self.context, ip1['id'],
                                          ports[0]['id'], _make_body('derp'))
            self.assertEqual('derp', updated_port.get('service'))

            filters = dict(device_id='a', service='derp')
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(1, len(ips))

            filters = dict(device_id='a', service='derp',
                           type=ip_types.FIXED)
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(0, len(ips))

            filters = dict(device_id='a', service='derp',
                           type=ip_types.SHARED)
            ips = ip_api.get_ip_addresses(self.context, **filters)
            self.assertEqual(1, len(ips))

    def test_get_ports_filter_with_ip_and_device(self):

        with self._stubs(self.network, self.subnet, self.ports_info4) as (
                net, sub, ports):

            network = dict(name="xx", tenant_id="fake", network_plugin="BASE")
            xx_network = {"network": network}
            xx_net = network_api.create_network(self.context, xx_network)
            subnet = dict(id=2, ip_version=4, next_auto_assign_ip=2,
                          cidr=self.cidr, first_ip=self.ip_network.first,
                          last_ip=self.ip_network.last, ip_policy=None,
                          tenant_id="fake")
            xx_subnet = {"subnet": subnet}
            xx_subnet['subnet']['network_id'] = xx_net['id']
            subnet_api.create_subnet(self.context, xx_subnet)

            port_info = {'port': dict(device_id='a')}
            port_info['port']['network_id'] = xx_net['id']
            port_api.create_port(self.context, port_info)

            port_ids1 = [ports[0]['id'], ports[1]['id']]

            shared_ip1 = {'ip_address': dict(port_ids=port_ids1,
                                             network_id=net['id'],
                                             version=4)}
            ip1 = ip_api.create_ip_address(self.context, shared_ip1)

            filters = dict(device_id='a')
            ports = ip_api.get_ports_for_ip_address(self.context, ip1['id'],
                                                    filters=filters)
            self.assertEqual(1, len(ports))

            filters = dict(device_id='a')
            ports = port_api.get_ports(self.context, filters=filters)
            self.assertEqual(2, len(ports))


class QuarkIPAddressFind(MySqlBaseFunctionalTest):
    def setUp(self):
        super(QuarkIPAddressFind, self).setUp()
        self.address = netaddr.IPAddress("0.0.0.1")
        db_api.ip_address_create(self.context, address=self.address)
        self.context.session.flush()

    def test_ip_address_find_address_integer(self):
        result = db_api.ip_address_find(
            self.context, address=int(self.address), scope=db_api.ONE)
        self.assertEqual(result.address_readable, str(self.address))

    def test_ip_address_find_address_string(self):
        result = db_api.ip_address_find(
            self.context, address=str(self.address), scope=db_api.ONE)
        self.assertEqual(result.address, int(self.address.ipv6()))
