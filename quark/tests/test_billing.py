# Copyright (c) 2016 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import json
import mock
from oslo_config import cfg
from quark import billing
from quark.db.models import IPAddress
from quark import network_strategy
from quark.tests import test_base
from quark import utils


class QuarkBillingBaseTest(test_base.TestBase):
    def setUp(self):
        super(QuarkBillingBaseTest, self).setUp()
        self.strategy = {"00000000-0000-0000-0000-000000000000":
                         {"bridge": "publicnet",
                          "subnets": {"4": "public_v4",
                                      "6": "public_v6"}}}
        strategy_json = json.dumps(self.strategy)
        cfg.CONF.set_override("default_net_strategy", strategy_json, "QUARK")
        network_strategy.STRATEGY.load()
        # Need to patch it here because billing has loaded before this
        # code is executed and had no config available to it.
        billing.PUBLIC_NETWORK_ID = \
            network_strategy.STRATEGY.get_public_net_id()


TENANT_ID = u'12345'
IP_ID = 'ffffffff-dddd-cccc-bbbb-aaaaaaaaaaaa'
IP_READABLE = '1.1.1.1'
SUBNET_ID = 'badc0ffe-dead-beef-c0fe-baaaaadc0ded'
PUB_NETWORK_ID = '00000000-0000-0000-0000-000000000000'


def get_fake_fixed_address():
    ipaddress = IPAddress()
    ipaddress.used_by_tenant_id = TENANT_ID
    ipaddress.version = 4
    ipaddress.id = IP_ID
    ipaddress.address_readable = IP_READABLE
    ipaddress.subnet_id = SUBNET_ID
    ipaddress.network_id = PUB_NETWORK_ID

    return ipaddress


class QuarkBillingPayloadTest(QuarkBillingBaseTest):
    """Tests for payload generation.

    This is the payload json:
    {
        'event_type': unicode(EVENT_TYPE_2_CLOUDFEEDS[event_type]),
        'tenant_id': unicode(ipaddress.used_by_tenant_id),
        'ip_address': unicode(ipaddress.address_readable),
        'subnet_id': unicode(ipaddress.subnet_id),
        'network_id': unicode(ipaddress.network_id),
        'public': True if ipaddress.network_id == PUBLIC_NETWORK_ID else False,
        'ip_version': int(ipaddress.version),
        'ip_type': unicode(ipaddress.address_type),
        'id': unicode(ipaddress.id)
    }
    """
    def setUp(self):
        super(QuarkBillingPayloadTest, self).setUp()

    def test_fixed_payload(self):
        start_time = datetime.datetime.utcnow().replace(microsecond=0) -\
            datetime.timedelta(days=1)
        end_time = datetime.datetime.utcnow().replace(microsecond=0)
        ipaddress = get_fake_fixed_address()
        ipaddress.allocated_at = start_time
        ipaddress.deallocated_at = end_time
        ipaddress.address_type = 'fixed'
        payload = billing.build_payload(ipaddress, billing.IP_EXISTS,
                                        start_time=start_time,
                                        end_time=end_time)
        self.assertEqual(payload['event_type'], billing.IP_EXISTS,
                         'event_type is wrong')
        self.assertEqual(payload['tenant_id'], TENANT_ID,
                         'tenant_id is wrong')
        self.assertEqual(payload['ip_address'], IP_READABLE,
                         'ip_address is wrong')
        self.assertEqual(payload['ip_version'], 4,
                         'ip_version should be 4')
        self.assertEqual(payload['ip_type'], 'fixed',
                         'ip_type should be fixed')
        self.assertEqual(payload['id'], IP_ID, 'ip_id is wrong')
        self.assertEqual(payload['startTime'],
                         billing.convert_timestamp(start_time),
                         'startTime is wrong')
        self.assertEqual(payload['endTime'],
                         billing.convert_timestamp(end_time),
                         'endTime is wrong')

    def test_associate_flip_payload(self):
        event_time = datetime.datetime.utcnow().replace(microsecond=0)
        ipaddress = get_fake_fixed_address()
        # allocated_at and deallocated_at could be anything for testing this
        ipaddress.allocated_at = event_time
        ipaddress.deallocated_at = event_time
        ipaddress.address_type = 'floating'
        payload = billing.build_payload(ipaddress, billing.IP_ASSOC,
                                        event_time=event_time)
        self.assertEqual(payload['event_type'], billing.IP_ASSOC,
                         'event_type is wrong')
        self.assertEqual(payload['tenant_id'], TENANT_ID, 'tenant_id is wrong')
        self.assertEqual(payload['ip_address'], IP_READABLE,
                         'ip_address is wrong')
        self.assertEqual(payload['subnet_id'], SUBNET_ID, 'subnet_id is wrong')
        self.assertEqual(payload['network_id'], PUB_NETWORK_ID,
                         'network_id is wrong')
        self.assertEqual(payload['public'], True, 'public should be true')
        self.assertEqual(payload['ip_version'], 4, 'ip_version should be 4')
        self.assertEqual(payload['ip_type'], 'floating',
                         'ip_type should be fixed')
        self.assertEqual(payload['id'], IP_ID, 'ip_id is wrong')
        self.assertEqual(payload['eventTime'],
                         billing.convert_timestamp(event_time),
                         'eventTime is wrong')

    def test_disassociate_flip_payload(self):
        event_time = datetime.datetime.utcnow().replace(microsecond=0)
        ipaddress = get_fake_fixed_address()
        # allocated_at and deallocated_at could be anything for testing this
        ipaddress.allocated_at = event_time
        ipaddress.deallocated_at = event_time
        ipaddress.address_type = 'floating'
        payload = billing.build_payload(ipaddress, billing.IP_DISASSOC,
                                        event_time=event_time)
        self.assertEqual(payload['event_type'], billing.IP_DISASSOC,
                         'event_type is wrong')
        self.assertEqual(payload['tenant_id'], TENANT_ID, 'tenant_id is wrong')
        self.assertEqual(payload['ip_address'], IP_READABLE,
                         'ip_address is wrong')
        self.assertEqual(payload['subnet_id'], SUBNET_ID, 'subnet_id is wrong')
        self.assertEqual(payload['network_id'], PUB_NETWORK_ID,
                         'network_id is wrong')
        self.assertEqual(payload['public'], True, 'public should be true')
        self.assertEqual(payload['ip_version'], 4, 'ip_version should be 4')
        self.assertEqual(payload['ip_type'], 'floating',
                         'ip_type should be fixed')
        self.assertEqual(payload['id'], IP_ID, 'ip_id is wrong')
        self.assertEqual(payload['eventTime'],
                         billing.convert_timestamp(event_time),
                         'eventTime is wrong')


class QuarkBillingEnvironmentCapabilityTest(QuarkBillingBaseTest):
    def setUp(self):
        super(QuarkBillingEnvironmentCapabilityTest, self).setUp()
        self.context = {}

    @mock.patch('neutron.common.rpc.get_notifier')
    def test_env_cap_enabled(self, notifier):
        cfg.CONF.set_override('environment_capabilities',
                              'security_groups,ip_billing',
                              'QUARK')
        ipaddress = get_fake_fixed_address()
        ipaddress.allocated_at = datetime.datetime.utcnow()
        billing.notify(self.context, billing.IP_ADD, ipaddress)
        notifier.assert_called_once_with('network')
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')

    @mock.patch('neutron.common.rpc.get_notifier')
    def test_env_cap_disabled(self, notifier):
        cfg.CONF.set_override('environment_capabilities',
                              '',
                              'QUARK')
        ipaddress = get_fake_fixed_address()
        ipaddress.allocated_at = datetime.datetime.utcnow()
        billing.notify(self.context, billing.IP_ADD, ipaddress)
        self.assertFalse(notifier.called)
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')

    @mock.patch('neutron.common.rpc.get_notifier')
    def test_do_not_notify_in_undo_cmd_mgr(self, notifier):
        """Wraps a call to notify in CommandManager's rollback()"""
        cfg.CONF.set_override('environment_capabilities',
                              'security_groups,ip_billing',
                              'QUARK')
        ipaddress = get_fake_fixed_address()
        ipaddress.allocated_at = datetime.datetime.utcnow()
        try:
            with utils.CommandManager().execute() as cmd_mgr:
                @cmd_mgr.do
                def f():
                    raise Exception

                @cmd_mgr.undo
                def f_undo(*args, **kwargs):
                    billing.notify(self.context, billing.IP_ADD, ipaddress,
                                   *args, **kwargs)

                f()
        except Exception:
            pass

        # notifier should NOT have been called
        self.assertFalse(notifier.called)
        cfg.CONF.clear_override('environment_capabilities', 'QUARK')
