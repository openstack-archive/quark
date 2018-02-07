import contextlib

import mock
import netaddr
from oslo_config import cfg
from oslo_log import log as logging
from quark import exceptions as q_exc
import quark.ipam
import quark.plugin_modules.ip_addresses as ip_api
import quark.plugin_modules.mac_address_ranges as macrng_api
import quark.plugin_modules.networks as network_api
import quark.plugin_modules.ports as port_api
import quark.plugin_modules.subnets as subnet_api
from quark.tests.functional.base import BaseFunctionalTest

LOG = logging.getLogger(__name__)


class QuarkTotalIpsPerPortQuotaCheck(BaseFunctionalTest):
    def __init__(self, *args, **kwargs):
        super(QuarkTotalIpsPerPortQuotaCheck, self).__init__(*args, **kwargs)
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
        port = {'port': dict(device_id='a')}
        self.ports = [port]
        self.old_cfg = cfg.CONF.QUARK.ipaddr_allow_fixed_ip

    def setUp(self):
        super(QuarkTotalIpsPerPortQuotaCheck, self).setUp()
        cfg.CONF.set_override('ipaddr_allow_fixed_ip', True, "QUARK")

    def tearDown(self):
        super(QuarkTotalIpsPerPortQuotaCheck, self).tearDown()
        cfg.CONF.set_override('ipaddr_allow_fixed_ip', self.old_cfg, "QUARK")

    @contextlib.contextmanager
    def _stubs(self, network_info, subnet_info, ports_info, keep_admin=False):
        self.ipam = quark.ipam.QuarkIpamANY()
        with mock.patch("neutron.common.rpc.get_notifier"):
            self.context.is_admin = True
            net = network_api.create_network(self.context, network_info)
            mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
            macrng_api.create_mac_address_range(self.context, mac)
            if not keep_admin:
                self.context.is_admin = False
            subnet_info['subnet']['network_id'] = net['id']
            sub = subnet_api.create_subnet(self.context, subnet_info)
            ports = []
            for port_info in ports_info:
                port_info['port']['network_id'] = net['id']
                ports.append(port_api.create_port(self.context, port_info))
            yield net, sub, ports

    def test_create_ip_over_public_network_quota(self):
        network = dict(name="public", tenant_id="fake", network_plugin="BASE",
                       id='00000000-0000-0000-0000-000000000000')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports) as (
                net, sub, ports):
            port_ids = [ports[0]['id']]
            ip_address = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE: This is hardcoded to 6. Port comes with an IP
            # Can create 5 more before it fails
            for i in xrange(5):
                ip_api.create_ip_address(self.context, ip_address)

            # NOTE: This should raise an exception
            with self.assertRaises(q_exc.CannotAddMoreIPsToPort):
                ip_api.create_ip_address(self.context, ip_address)

    def test_create_ip_over_isolated_network_quota(self):
        with self._stubs(self.network, self.subnet, self.ports) as (
                net, sub, ports):
            port_ids = [ports[0]['id']]
            ip_address = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE: This is hardcoded to 5. Port comes with an IP
            # Can create 4 more before it fails
            for i in xrange(4):
                ip_api.create_ip_address(self.context, ip_address)

            # NOTE: This should raise an exception
            with self.assertRaises(q_exc.CannotAddMoreIPsToPort):
                ip_api.create_ip_address(self.context, ip_address)

    def test_create_ip_over_service_network_quota(self):
        network = dict(name="service", network_plugin="BASE",
                       id='11111111-1111-1111-1111-111111111111')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports) as (
                net, sub, ports):
            port_ids = [ports[0]['id']]
            ip_address = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE : This is hardcoded to 1 and should raise an exception
            # as ports come with 1 IP
            with self.assertRaises(q_exc.CannotAddMoreIPsToPort):
                ip_api.create_ip_address(self.context, ip_address)

    def test_create_ip_over_public_network_quota_admin_context(self):
        network = dict(name="public", network_plugin="BASE",
                       id='00000000-0000-0000-0000-000000000000')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports,
                         keep_admin=True) as (net, sub, ports):
            port_ids = [ports[0]['id']]
            ip_address = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE: This is hardcoded to 6. Port comes with an IP
            # can create 5 more before it fails
            for i in xrange(5):
                ip_api.create_ip_address(self.context, ip_address)

            # NOTE: This should raise an exception
            with self.assertRaises(q_exc.CannotAddMoreIPsToPort):
                ip_api.create_ip_address(self.context, ip_address)

    def test_create_ip_over_isolated_network_quota_admin_context(self):
        with self._stubs(self.network, self.subnet, self.ports,
                         keep_admin=True) as (net, sub, ports):
            port_ids = [ports[0]['id']]
            ip_address = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE: This is hardcoded to 5. Port comes with an IP
            # can create 4 more before it fails
            for i in xrange(4):
                ip_api.create_ip_address(self.context, ip_address)

            # NOTE: This should raise an exception
            with self.assertRaises(q_exc.CannotAddMoreIPsToPort):
                ip_api.create_ip_address(self.context, ip_address)

    def test_create_ip_over_service_network_quota_admin_context(self):
        network = dict(name="service", tenant_id="fake", network_plugin="BASE",
                       id='11111111-1111-1111-1111-111111111111')
        network = {"network": network}

        with self._stubs(network, self.subnet, self.ports,
                         keep_admin=True) as (net, sub, ports):
            port_ids = [ports[0]['id']]
            ip_address = {'ip_address': dict(port_ids=port_ids,
                                             network_id=net['id'],
                                             version=4)}

            # NOTE : This is hardcoded to 1 and should raise an exception
            # as ports come with 1 IP
            with self.assertRaises(q_exc.CannotAddMoreIPsToPort):
                ip_api.create_ip_address(self.context, ip_address)
