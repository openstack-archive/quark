import json
import mock
import netaddr
from neutron import context
from oslo_config import cfg

from quark.db import api as db_api
from quark import exceptions as qexceptions
import quark.ipam
from quark import network_strategy
import quark.plugin
import quark.plugin_modules.mac_address_ranges as macrng_api
from quark.tests.functional import base


class BaseFloatingIPTest(base.BaseFunctionalTest):

    FAKE_UNICORN_URL = 'http://unicorn.xxx'

    def _setup_mock_requests(self):
        cfg.CONF.set_override('floating_ip_base_url', self.FAKE_UNICORN_URL,
                              group='QUARK')
        patcher = mock.patch('quark.drivers.unicorn_driver.requests')
        self.mock_requests = patcher.start()
        self.addCleanup(patcher.stop)
        self.mock_requests.post.return_value.status_code = 200
        self.mock_requests.delete.return_value.status_code = 204
        self.mock_requests.put.return_value.status_code = 200

    def _build_expected_unicorn_request_body(self, floating_ip_address, ports,
                                             actual_body=None):
        if actual_body:
            # Since the port order is non-deterministic, we need to ensure
            # that the order is correct
            actual_port_ids = [endpoint['port']['uuid'] for endpoint in
                               actual_body['floating_ip']['endpoints']]
            reordered_ports = []
            for port_id in actual_port_ids:
                for port in ports:
                    if port['id'] == port_id:
                        reordered_ports.append(port)
            ports = reordered_ports
        endpoints = []
        for port in ports:
            fixed_ips = []
            for fixed_ip in port['fixed_ips']:
                fixed_ips.append({
                    'ip_address': fixed_ip['ip_address'],
                    'version': self.user_subnet['ip_version'],
                    'subnet_id': self.user_subnet['id'],
                    'cidr': self.user_subnet['cidr'],
                    'address_type': 'fixed'
                })
            port_mac = int(netaddr.EUI(port['mac_address'].replace(':', '-')))
            endpoints.append({
                'port': {
                    'uuid': port['id'],
                    'name': port['name'],
                    'network_uuid': port['network_id'],
                    'mac_address': port_mac,
                    'device_id': port['device_id'],
                    'device_owner': port['device_owner'],
                    'fixed_ip': fixed_ips
                },
                'private_ip': port['fixed_ips'][0]['ip_address']
            })
        body = {'public_ip': floating_ip_address,
                'endpoints': endpoints}
        return {'floating_ip': body}

    def setUp(self):
        super(BaseFloatingIPTest, self).setUp()
        self.public_net_id = "00000000-0000-0000-0000-000000000000"
        net_stat = '{"%s": {}}' % self.public_net_id
        cfg.CONF.set_override('default_net_strategy', net_stat, group='QUARK')
        old_strat = db_api.STRATEGY

        def reset_strategy():
            db_api.STRATEGY = old_strat

        db_api.STRATEGY = network_strategy.JSONStrategy()
        self.addCleanup(reset_strategy)
        admin_ctx = context.get_admin_context()
        self._setup_mock_requests()
        self.plugin = quark.plugin.Plugin()
        mac = {'mac_address_range': dict(cidr="AA:BB:CC")}
        macrng_api.create_mac_address_range(admin_ctx, mac)
        with admin_ctx.session.begin():
            tenant = 'rackspace'
            floating_net = dict(name='publicnet', tenant_id=tenant,
                                id=self.public_net_id)
            self.floating_network = db_api.network_create(
                self.context, **floating_net)
            self.pub_net_cidr = "10.1.1.0/24"
            floating_subnet = dict(id=self.public_net_id,
                                   cidr=self.pub_net_cidr,
                                   ip_policy=None, tenant_id=tenant,
                                   segment_id='floating_ip',
                                   network_id=self.floating_network.id)
            self.floating_subnet = db_api.subnet_create(
                self.context, **floating_subnet)
        user_net = dict(name='user_network', tenant_id='fake')
        self.user_network = self.plugin.create_network(
            self.context, {'network': user_net})
        user_subnet = dict(cidr="192.168.1.0/24",
                           ip_policy=None, tenant_id="fake",
                           network_id=self.user_network['id'])
        self.user_subnet = self.plugin.create_subnet(
            self.context, {'subnet': user_subnet})
        user_port1 = dict(name='user_port1',
                          network_id=self.user_network['id'])
        self.user_port1 = self.plugin.create_port(
            self.context, {'port': user_port1})
        user_port2 = dict(name='user_port2',
                          network_id=self.user_network['id'])
        self.user_port2 = self.plugin.create_port(
            self.context, {'port': user_port2})


class TestFloatingIPs(BaseFloatingIPTest):

    def test_create(self):
        flip_req = dict(
            floating_network_id=self.floating_network['id'],
            port_id=self.user_port1['id']
        )
        flip_req = {'floatingip': flip_req}
        flip = self.plugin.create_floatingip(self.context, flip_req)
        self.assertIn(netaddr.IPAddress(flip['floating_ip_address']),
                      list(netaddr.IPNetwork(self.pub_net_cidr)))
        self.assertEqual(self.floating_network['id'],
                         flip['floating_network_id'])
        self.assertEqual(self.user_port1['id'], flip['port_id'])
        self.assertEqual(self.user_port1['fixed_ips'][0]['ip_address'],
                         flip['fixed_ip_address'])
        self.mock_requests.post.assert_called_once_with(
            self.FAKE_UNICORN_URL, data=mock.ANY, timeout=2
        )
        actual_body = json.loads(self.mock_requests.post.call_args[1]['data'])
        unicorn_body = self._build_expected_unicorn_request_body(
            flip['floating_ip_address'], [self.user_port1]
        )
        self.assertEqual(unicorn_body, actual_body,
                         msg="Request to the unicorn API is not what is "
                             "expected.")
        get_flip = self.plugin.get_floatingip(self.context, flip['id'])
        self.assertEqual(flip['floating_ip_address'],
                         get_flip['floating_ip_address'])

    def test_update_floating_ip(self):
        floating_ip = dict(
            floating_network_id=self.floating_network.id,
            port_id=self.user_port1['id']
        )
        floating_ip = {'floatingip': floating_ip}
        flip = self.plugin.create_floatingip(self.context, floating_ip)
        fixed_ip_address2 = self.user_port2['fixed_ips'][0]['ip_address']
        floating_ip = dict(port_id=self.user_port2['id'],
                           fixed_ip_address=fixed_ip_address2)
        updated_flip = self.plugin.update_floatingip(
            self.context, flip['id'], {"floatingip": floating_ip})
        self.assertEqual(self.floating_network['id'],
                         updated_flip['floating_network_id'])
        self.assertEqual(updated_flip['floating_ip_address'],
                         flip['floating_ip_address'])
        self.assertEqual(self.user_port2['id'], updated_flip['port_id'])
        self.assertEqual(self.user_port2['fixed_ips'][0]['ip_address'],
                         updated_flip['fixed_ip_address'])
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 flip['floating_ip_address']])
        self.mock_requests.put.assert_called_once_with(
            expected_url, data=mock.ANY, timeout=2
        )
        actual_body = json.loads(self.mock_requests.put.call_args[1]['data'])
        unicorn_body = self._build_expected_unicorn_request_body(
            flip['floating_ip_address'], [self.user_port2]
        )
        self.assertEqual(unicorn_body, actual_body,
                         msg="Request to the unicorn API is not what is "
                             "expected.")
        get_flip = self.plugin.get_floatingip(self.context, flip['id'])
        self.assertEqual(flip['floating_ip_address'],
                         get_flip['floating_ip_address'])

    @mock.patch('quark.billing.notify')
    @mock.patch('quark.billing.build_payload', return_value={})
    def test_delete_floating_ip(self, notify, build_payload):
        floating_ip = dict(
            floating_network_id=self.floating_network.id,
            port_id=self.user_port1['id'],
            address_type='floating'
        )
        flip = self.plugin.create_floatingip(
            self.context, {"floatingip": floating_ip})
        self.plugin.delete_floatingip(self.context, flip['id'])
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 flip['floating_ip_address']])
        self.mock_requests.delete.assert_called_once_with(
            expected_url, timeout=2
        )
        self.assertRaises(qexceptions.FloatingIpNotFound,
                          self.plugin.get_floatingip, self.context, flip['id'])
        flips = self.plugin.get_floatingips(self.context)
        self.assertEqual(0, len(flips))
