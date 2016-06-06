import json
import mock
import netaddr
from neutron_lib import exceptions as n_exc

from quark import exceptions as qexceptions
from quark.tests.functional.plugin_modules import test_floating_ips


class TestScalingIP(test_floating_ips.BaseFloatingIPTest):

    def setUp(self):
        super(TestScalingIP, self).setUp()
        self.scaling_network = self.floating_network

    def test_create_scaling_ip(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id']),
                   dict(port_id=self.user_port2['id'])]
        )
        scaling_ip = {'scalingip': scaling_ip}
        scip = self.plugin.create_scalingip(self.context, scaling_ip)
        self.assertIn(netaddr.IPAddress(scip['scaling_ip_address']),
                      list(netaddr.IPNetwork(self.pub_net_cidr)))
        self.assertEqual(self.scaling_network['id'],
                         scip['scaling_network_id'])
        self.assertEqual(2, len(scip['ports']))
        scip_ports = {scip_port['port_id']: scip_port['fixed_ip_address']
                      for scip_port in scip['ports']}
        port1_fixed_ip = self.user_port1['fixed_ips'][0]['ip_address']
        port2_fixed_ip = self.user_port2['fixed_ips'][0]['ip_address']
        self.assertIn(self.user_port1['id'], scip_ports)
        self.assertIn(self.user_port2['id'], scip_ports)
        self.assertIn(port1_fixed_ip, scip_ports.values())
        self.assertIn(port2_fixed_ip, scip_ports.values())
        self.mock_requests.post.assert_called_once_with(
            self.FAKE_UNICORN_URL, data=mock.ANY, timeout=2
        )
        actual_body = json.loads(self.mock_requests.post.call_args[1]['data'])
        unicorn_body = self._build_expected_unicorn_request_body(
            scip['scaling_ip_address'], [self.user_port1, self.user_port2],
            actual_body=actual_body
        )
        self.assertEqual(unicorn_body, actual_body,
                         msg="Request to the unicorn API is not what is "
                             "expected.")
        get_scip = self.plugin.get_scalingip(self.context, scip['id'])
        self.assertEqual(scip['scaling_ip_address'],
                         get_scip['scaling_ip_address'])

    def test_create_with_invalid_scaling_network_id(self):
        scaling_ip = dict(
            scaling_network_id='some-wrong-network-id',
            ports=[dict(port_id=self.user_port1['id']),
                   dict(port_id=self.user_port2['id'])]
        )
        self.assertRaises(n_exc.NetworkNotFound,
                          self.plugin.create_scalingip,
                          self.context, {"scalingip": scaling_ip})

    def test_create_with_scaling_network_invalid_segment(self):
        scaling_ip = dict(
            scaling_network_id=self.user_network['id'],
            ports=[dict(port_id=self.user_port1['id']),
                   dict(port_id=self.user_port2['id'])]
        )
        self.assertRaises(n_exc.IpAddressGenerationFailure,
                          self.plugin.create_scalingip,
                          self.context, {"scalingip": scaling_ip})

    def test_update_scaling_ip_add_port(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id'])]
        )
        scaling_ip = {'scalingip': scaling_ip}
        scip = self.plugin.create_scalingip(self.context, scaling_ip)
        self.mock_requests.reset_mock()
        scaling_ip = dict(ports=[dict(port_id=self.user_port1['id']),
                                 dict(port_id=self.user_port2['id'])])
        updated_scip = self.plugin.update_scalingip(
            self.context, scip['id'], {"scalingip": scaling_ip})
        self.assertEqual(self.scaling_network['id'],
                         updated_scip['scaling_network_id'])
        self.assertEqual(updated_scip['scaling_ip_address'],
                         scip['scaling_ip_address'])
        self.assertEqual(2, len(updated_scip['ports']))
        scip_ports = {scip_port['port_id']: scip_port['fixed_ip_address']
                      for scip_port in updated_scip['ports']}
        port1_fixed_ip = self.user_port1['fixed_ips'][0]['ip_address']
        port2_fixed_ip = self.user_port2['fixed_ips'][0]['ip_address']
        self.assertIn(self.user_port1['id'], scip_ports)
        self.assertIn(self.user_port2['id'], scip_ports)
        self.assertIn(port1_fixed_ip, scip_ports.values())
        self.assertIn(port2_fixed_ip, scip_ports.values())
        self.assertFalse(self.mock_requests.post.called)
        self.assertFalse(self.mock_requests.delete.called)
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 scip['scaling_ip_address']])
        self.mock_requests.put.assert_called_once_with(
            expected_url, data=mock.ANY, timeout=2)
        actual_body = json.loads(self.mock_requests.put.call_args[1]['data'])
        unicorn_body = self._build_expected_unicorn_request_body(
            scip['scaling_ip_address'], [self.user_port1, self.user_port2],
            actual_body=actual_body
        )
        self.assertEqual(unicorn_body, actual_body,
                         msg="Request to the unicorn API is not what is "
                             "expected.")

    def test_update_scaling_ip_remove_port_with_remaining_ports(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id']),
                   dict(port_id=self.user_port2['id'])]
        )
        scaling_ip = {'scalingip': scaling_ip}
        scip = self.plugin.create_scalingip(self.context, scaling_ip)
        self.mock_requests.reset_mock()
        scaling_ip = dict(ports=[dict(port_id=self.user_port1['id'])])
        updated_scip = self.plugin.update_scalingip(
            self.context, scip['id'], {"scalingip": scaling_ip})
        self.assertEqual(self.scaling_network['id'],
                         updated_scip['scaling_network_id'])
        self.assertEqual(updated_scip['scaling_ip_address'],
                         scip['scaling_ip_address'])
        self.assertEqual(1, len(updated_scip['ports']))
        scip_ports = {scip_port['port_id']: scip_port['fixed_ip_address']
                      for scip_port in updated_scip['ports']}
        port1_fixed_ip = self.user_port1['fixed_ips'][0]['ip_address']
        self.assertIn(self.user_port1['id'], scip_ports)
        self.assertIn(port1_fixed_ip, scip_ports.values())
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 scip['scaling_ip_address']])
        self.assertFalse(self.mock_requests.post.called)
        self.assertFalse(self.mock_requests.delete.called)
        self.mock_requests.put.assert_called_once_with(
            expected_url, data=mock.ANY, timeout=2)
        actual_body = json.loads(self.mock_requests.put.call_args[1]['data'])
        unicorn_body = self._build_expected_unicorn_request_body(
            scip['scaling_ip_address'], [self.user_port1],
            actual_body=actual_body
        )
        self.assertEqual(unicorn_body, actual_body,
                         msg="Request to the unicorn API is not what is "
                             "expected.")

    def test_update_scaling_ip_clear_ports(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id']),
                   dict(port_id=self.user_port2['id'])]
        )
        scaling_ip = {'scalingip': scaling_ip}
        scip = self.plugin.create_scalingip(self.context, scaling_ip)
        self.mock_requests.reset_mock()
        scaling_ip = dict(ports=[])
        updated_scip = self.plugin.update_scalingip(
            self.context, scip['id'], {"scalingip": scaling_ip})
        self.assertEqual(self.scaling_network['id'],
                         updated_scip['scaling_network_id'])
        self.assertEqual(updated_scip['scaling_ip_address'],
                         scip['scaling_ip_address'])
        self.assertEqual(0, len(updated_scip['ports']))
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 scip['scaling_ip_address']])
        self.assertFalse(self.mock_requests.post.called)
        self.assertFalse(self.mock_requests.put.called)
        self.mock_requests.delete.assert_called_once_with(
            expected_url, timeout=2)

    def test_update_scaling_ip_add_ports_from_none(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[]
        )
        scaling_ip = {'scalingip': scaling_ip}
        scip = self.plugin.create_scalingip(self.context, scaling_ip)
        self.mock_requests.reset_mock()
        scaling_ip = dict(ports=[dict(port_id=self.user_port1['id']),
                                 dict(port_id=self.user_port2['id'])])
        updated_scip = self.plugin.update_scalingip(
            self.context, scip['id'], {"scalingip": scaling_ip})
        self.assertEqual(self.scaling_network['id'],
                         updated_scip['scaling_network_id'])
        self.assertEqual(updated_scip['scaling_ip_address'],
                         scip['scaling_ip_address'])
        self.assertEqual(2, len(updated_scip['ports']))
        scip_ports = {scip_port['port_id']: scip_port['fixed_ip_address']
                      for scip_port in updated_scip['ports']}
        port1_fixed_ip = self.user_port1['fixed_ips'][0]['ip_address']
        port2_fixed_ip = self.user_port2['fixed_ips'][0]['ip_address']
        self.assertIn(self.user_port1['id'], scip_ports)
        self.assertIn(self.user_port2['id'], scip_ports)
        self.assertIn(port1_fixed_ip, scip_ports.values())
        self.assertIn(port2_fixed_ip, scip_ports.values())
        self.assertFalse(self.mock_requests.put.called)
        self.assertFalse(self.mock_requests.delete.called)
        self.mock_requests.post.assert_called_once_with(
            self.FAKE_UNICORN_URL, data=mock.ANY, timeout=2)
        actual_body = json.loads(self.mock_requests.post.call_args[1]['data'])
        unicorn_body = self._build_expected_unicorn_request_body(
            scip['scaling_ip_address'], [self.user_port1, self.user_port2],
            actual_body=actual_body
        )
        self.assertEqual(unicorn_body, actual_body,
                         msg="Request to the unicorn API is not what is "
                             "expected.")

    @mock.patch('quark.billing.notify')
    @mock.patch('quark.billing.build_payload', return_value={})
    def test_delete_scaling_ip(self, notify, build_payload):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id']),
                   dict(port_id=self.user_port2['id'])]
        )
        scip = self.plugin.create_scalingip(
            self.context, {"scalingip": scaling_ip})
        self.plugin.delete_scalingip(self.context, scip['id'])
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 scip['scaling_ip_address']])
        self.mock_requests.delete.assert_called_once_with(
            expected_url, timeout=2
        )
        self.assertRaises(qexceptions.ScalingIpNotFound,
                          self.plugin.get_scalingip, self.context, scip['id'])
        scips = self.plugin.get_scalingips(self.context)
        self.assertEqual(0, len(scips))

    def test_scaling_ip_not_in_floating_ip_list(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id'])]
        )
        scaling_ip = {'scalingip': scaling_ip}
        self.plugin.create_scalingip(self.context, scaling_ip)
        flips = self.plugin.get_floatingips(self.context)
        self.assertEqual(0, len(flips))

    def test_floating_ip_not_in_scaling_ip_list(self):
        floating_ip = dict(
            floating_network_id=self.scaling_network.id,
            port_id=self.user_port1['id']
        )
        floating_ip = {'floatingip': floating_ip}
        self.plugin.create_floatingip(self.context, floating_ip)
        scips = self.plugin.get_scalingips(self.context)
        self.assertEqual(0, len(scips))

    def test_delete_port_associated_with_scip_with_multiple_ports(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id']),
                   dict(port_id=self.user_port2['id'])]
        )
        scip = self.plugin.create_scalingip(
            self.context, {"scalingip": scaling_ip})
        self.mock_requests.reset_mock()
        self.context.session.expire_all()
        self.plugin.delete_port(self.context, self.user_port1['id'])
        after_scip = self.plugin.get_scalingip(self.context, scip['id'])
        self.assertEqual(1, len(after_scip['ports']))
        self.assertEqual(self.user_port2['id'],
                         after_scip['ports'][0]['port_id'])
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 scip['scaling_ip_address']])
        self.assertFalse(self.mock_requests.post.called)
        self.assertFalse(self.mock_requests.delete.called)
        self.mock_requests.put.assert_called_once_with(
            expected_url, data=mock.ANY, timeout=2)
        actual_body = json.loads(self.mock_requests.put.call_args[1]['data'])
        unicorn_body = self._build_expected_unicorn_request_body(
            scip['scaling_ip_address'], [self.user_port2],
            actual_body=actual_body
        )
        self.assertEqual(unicorn_body, actual_body,
                         msg="Request to the unicorn API is not what is "
                             "expected.")

    def test_delete_port_associated_with_scip_with_one_port(self):
        scaling_ip = dict(
            scaling_network_id=self.scaling_network.id,
            ports=[dict(port_id=self.user_port1['id'])]
        )
        scip = self.plugin.create_scalingip(
            self.context, {"scalingip": scaling_ip})
        self.mock_requests.reset_mock()
        self.context.session.expire_all()
        self.plugin.delete_port(self.context, self.user_port1['id'])
        after_scip = self.plugin.get_scalingip(self.context, scip['id'])
        self.assertEqual(0, len(after_scip['ports']))
        expected_url = '/'.join([self.FAKE_UNICORN_URL,
                                 scip['scaling_ip_address']])
        self.assertFalse(self.mock_requests.post.called)
        self.assertFalse(self.mock_requests.put.called)
        self.mock_requests.delete.assert_called_once_with(
            expected_url, timeout=2)
