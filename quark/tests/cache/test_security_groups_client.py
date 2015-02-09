# Copyright 2014 Openstack Foundation
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#

import json

import mock
import netaddr
from oslo.config import cfg
import redis

from quark.agent.xapi import VIF
from quark.cache import security_groups_client as sg_client
from quark.db import models
from quark import exceptions as q_exc
from quark.tests import test_base

CONF = cfg.CONF


class TestRedisSecurityGroupsClient(test_base.TestBase):

    def setUp(self):
        super(TestRedisSecurityGroupsClient, self).setUp()
        # Forces the connection pool to be recreated on every test
        sg_client.SecurityGroupsClient.connection_pool = None

    @mock.patch("uuid.uuid4")
    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.cache.redis_base.redis.StrictRedis")
    def test_apply_rules(self, strict_redis, conn_pool, uuid4):
        client = sg_client.SecurityGroupsClient(use_master=True)
        device_id = "device"
        uuid4.return_value = "uuid"

        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        client.apply_rules(device_id, mac_address.value, [])
        self.assertTrue(client._client.hset.called)

        redis_key = client.vif_key(device_id, mac_address.value)

        rule_dict = {"rules": [], "id": "uuid"}
        client._client.hset.assert_called_with(
            redis_key, sg_client.SECURITY_GROUP_HASH_ATTR,
            json.dumps(rule_dict))

    @mock.patch("uuid.uuid4")
    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.cache.redis_base.redis.StrictRedis")
    def test_delete_vif(self, strict_redis, conn_pool, uuid4):
        client = sg_client.SecurityGroupsClient(use_master=True)
        device_id = "device"
        uuid4.return_value = "uuid"
        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        redis_key = client.vif_key(device_id, mac_address.value)
        client.delete_vif(device_id, mac_address)
        client._client.delete.assert_called_with(redis_key)

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.SecurityGroupsClient.vif_key")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_apply_rules_with_slave_fails(self, strict_redis, vif_key,
                                          conn_pool):
        client = sg_client.SecurityGroupsClient()
        port_id = 1
        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        with self.assertRaises(q_exc.RedisSlaveWritesForbidden):
            client.apply_rules(port_id, mac_address.value, [])

    @mock.patch("redis.ConnectionPool")
    def test_apply_rules_set_fails_gracefully(self, conn_pool):
        port_id = 1
        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        conn_err = redis.ConnectionError
        with mock.patch("redis.StrictRedis") as redis_mock:
            mocked_redis_cli = mock.MagicMock()
            redis_mock.return_value = mocked_redis_cli

            client = sg_client.SecurityGroupsClient(use_master=True)
            mocked_redis_cli.hset.side_effect = conn_err
            with self.assertRaises(q_exc.RedisConnectionFailure):
                client.apply_rules(port_id, mac_address.value, [])

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_group_no_rules(self, strict_redis, conn_pool):
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        payload = client.serialize_groups([group])
        self.assertEqual([], payload)

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_group_with_rules(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 6, "port_range_min": 80,
                     "port_range_max": 443, "direction": "ingress"}
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x800, rule["ethertype"])
        self.assertEqual(6, rule["protocol"])
        self.assertEqual(80, rule["port start"])
        self.assertEqual(443, rule["port end"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("", rule["source network"])
        self.assertEqual("", rule["destination network"])

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_group_with_rules_and_remote_network(self, strict_redis,
                                                           conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 1, "direction": "ingress",
                     "remote_ip_prefix": "192.168.0.0/24"}
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x800, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["icmp type"])
        self.assertEqual(None, rule["icmp code"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("::ffff:192.168.0.0/120", rule["source network"])
        self.assertEqual("", rule["destination network"])

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_group_egress_rules(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 1,
                     "direction": "egress",
                     "remote_ip_prefix": "192.168.0.0/24"}
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x800, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["icmp type"])
        self.assertEqual(None, rule["icmp code"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("::ffff:192.168.0.0/120", rule["destination network"])
        self.assertEqual("", rule["source network"])

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_filters_source_v4_net(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 1, "direction": "ingress",
                     "remote_ip_prefix": "192.168.0.0/0"}
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x800, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["icmp type"])
        self.assertEqual(None, rule["icmp code"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("", rule["source network"])
        self.assertEqual("", rule["destination network"])

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_filters_source_v6_net(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x86DD, "protocol": 1,
                     "direction": "ingress",
                     "remote_ip_prefix": "feed::/0"}
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x86DD, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["icmp type"])
        self.assertEqual(None, rule["icmp code"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("", rule["source network"])
        self.assertEqual("", rule["destination network"])

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_filters_dest_v4_net(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 1, "direction": "egress",
                     "remote_ip_prefix": "192.168.0.0/0"}
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x800, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["icmp type"])
        self.assertEqual(None, rule["icmp code"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("", rule["source network"])
        self.assertEqual("", rule["destination network"])

    @mock.patch("redis.ConnectionPool")
    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_serialize_filters_dest_v6_net(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x86DD, "protocol": 1,
                     "direction": "egress",
                     "remote_ip_prefix": "feed::/0"}
        client = sg_client.SecurityGroupsClient()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x86DD, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["icmp type"])
        self.assertEqual(None, rule["icmp code"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("", rule["source network"])
        self.assertEqual("", rule["destination network"])


class TestRedisForAgent(test_base.TestBase):
    def setUp(self):
        super(TestRedisForAgent, self).setUp()

        patch = mock.patch("quark.cache.security_groups_client.redis_base."
                           "redis.StrictRedis")
        self.MockSentinel = patch.start()
        self.addCleanup(patch.stop)

    @mock.patch(
        "quark.cache.security_groups_client.redis_base.redis.StrictRedis")
    def test_get_security_groups_empty(self, strict_redis):
        mock_redis = mock.MagicMock()
        mock_pipeline = mock.MagicMock()
        strict_redis.return_value = mock_redis
        mock_redis.pipeline.return_value = mock_pipeline

        rc = sg_client.SecurityGroupsClient()
        group_uuids = rc.get_security_groups(set())
        mock_redis.pipeline.assert_called_once_with()
        self.assertEqual(mock_pipeline.get.call_count, 0)
        mock_pipeline.execute.assert_called_once_with()
        self.assertEqual(group_uuids, {})

    @mock.patch(
        "quark.cache.security_groups_client.SecurityGroupsClient.get_fields")
    def test_get_security_groups_nonempty(self, mock_get_fields):
        rc = sg_client.SecurityGroupsClient()

        mock_get_fields.return_value = [
            None,
            '{}',
            '{"%s": null}' % sg_client.SECURITY_GROUP_VERSION_UUID_KEY,
            '{"%s": "1-2-3"}' % sg_client.SECURITY_GROUP_VERSION_UUID_KEY]

        new_interfaces = ([VIF(1, 2, 9), VIF(3, 4, 0), VIF(5, 6, 1),
                           VIF(7, 8, 2)])

        group_uuids = rc.get_security_groups(new_interfaces)

        mock_get_fields.assert_called_once_with(
            ["1.000000000002", "3.000000000004", "5.000000000006",
             "7.000000000008"], sg_client.SECURITY_GROUP_HASH_ATTR)

        self.assertEqual(group_uuids,
                         {VIF(1, 2, 9): None,
                          VIF(3, 4, 0): None,
                          VIF(5, 6, 1): None,
                          VIF(7, 8, 2): "1-2-3"})
