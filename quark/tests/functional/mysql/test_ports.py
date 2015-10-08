import mock
import netaddr

import contextlib

from quark.db import api as db_api
from quark import exceptions
import quark.ipam
import quark.plugin
import quark.plugin_modules.ip_addresses as ip_api
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.mysql.base import MySqlBaseFunctionalTest


class QuarkUpdatePorts(MySqlBaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_info, port_info):
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
            port_info['port']['network_id'] = net['id']
            sub = subnet_api.create_subnet(self.context, subnet_info)
            port = port_api.create_port(self.context, port_info)
            yield net, sub, port

    def test_update_fixed_ips_regression_RM9097(self):
        cidr = "192.168.1.0/24"
        ip_network = netaddr.IPNetwork(cidr)
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        network = {"network": network}
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr=cidr, first_ip=ip_network.first,
                      last_ip=ip_network.last, ip_policy=None,
                      tenant_id="fake")
        subnet = {"subnet": subnet}
        port = {"port": dict()}

        def _make_body(ip):
            fix_ip = dict(ip_address=ip, subnet_id=sub['id'])
            port_info = {"port": dict(fixed_ips=[fix_ip])}
            return port_info

        with self._stubs(network, subnet, port) as (net, sub, port):
            id = port['id']

            ip = "192.168.1.50"
            port = port_api.update_port(self.context, id, _make_body(ip))
            self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])

            with self.assertRaises(exceptions.IPAddressNotInSubnet):
                ip = "192.168.2.50"
                port = port_api.update_port(self.context, id, _make_body(ip))
                self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])

            ip = "192.168.1.75"
            port = port_api.update_port(self.context, id, _make_body(ip))
            self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])

            ip = "192.168.1.50"
            port = port_api.update_port(self.context, id, _make_body(ip))
            self.assertEqual(ip, port['fixed_ips'][0]['ip_address'])


class QuarkFindPorts(MySqlBaseFunctionalTest):
    def test_ip_address_port_find_service(self):
        net = db_api.network_create(self.context)
        port = db_api.port_create(self.context, network_id=net["id"],
                                  backend_key="", device_id="")
        ip_address = db_api.ip_address_create(
            self.context, address=netaddr.IPAddress("0.0.0.0"))
        self.context.session.flush()

        ip_address = db_api.port_associate_ip(self.context, [port], ip_address)
        ip_address.set_service_for_port(port, "foobar")
        self.context.session.flush()

        ports = ip_api.get_ports_for_ip_address(
            self.context, ip_address["id"],
            filters={"service": "not-foobar"})
        self.assertEqual(len(ports), 0)

        ports = ip_api.get_ports_for_ip_address(
            self.context, ip_address["id"],
            filters={"service": "foobar"})
        self.assertEqual(len(ports), 1)
