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

import contextlib
import json
import uuid

import mock
import netaddr
from oslo.config import cfg
import redis

from quark.agent.xapi import VIF
from quark.db import models
from quark import exceptions as q_exc
from quark.security_groups import redis_client
from quark.tests import test_base

CONF = cfg.CONF


class TestRedisSerialization(test_base.TestBase):
    def setUp(self):
        super(TestRedisSerialization, self).setUp()
        # Forces the connection pool to be recreated on every test
        redis_client.Client.connection_pool = None

    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_redis_key(self, strict_redis, conn_pool):
        host = "127.0.0.1"
        port = 6379
        client = redis_client.Client()
        device_id = str(uuid.uuid4())
        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        redis_key = client.rule_key(device_id, mac_address.value)
        expected = "%s.%s" % (device_id, "aabbccddeeff")
        self.assertEqual(expected, redis_key)
        conn_pool.assert_called_with(host=host, port=port)

    @mock.patch("uuid.uuid4")
    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_apply_rules(self, strict_redis, conn_pool, uuid4):
        client = redis_client.Client(use_master=True)
        device_id = "device"
        uuid4.return_value = "uuid"

        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        client.apply_rules(device_id, mac_address.value, [])
        self.assertTrue(client._client.hset.called)

        redis_key = client.rule_key(device_id, mac_address.value)

        rule_dict = {"rules": [], "id": "uuid"}
        client._client.hset.assert_called_with(
            redis_key, "sg", json.dumps(rule_dict))

    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.security_groups.redis_client.Client.rule_key")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_apply_rules_with_slave_fails(self, strict_redis, rule_key,
                                          conn_pool):
        client = redis_client.Client()
        port_id = 1
        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        with self.assertRaises(q_exc.RedisSlaveWritesForbidden):
            client.apply_rules(port_id, mac_address.value, [])

    @mock.patch("redis.ConnectionPool")
    def test_client_connection_fails_gracefully(self, conn_pool):
        conn_err = redis.ConnectionError
        with mock.patch("redis.StrictRedis") as redis_mock:
            redis_mock.side_effect = conn_err
            with self.assertRaises(q_exc.RedisConnectionFailure):
                redis_client.Client(use_master=True)

    @mock.patch("redis.ConnectionPool")
    def test_apply_rules_set_fails_gracefully(self, conn_pool):
        port_id = 1
        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")
        conn_err = redis.ConnectionError
        with mock.patch("redis.StrictRedis") as redis_mock:
            mocked_redis_cli = mock.MagicMock()
            redis_mock.return_value = mocked_redis_cli

            client = redis_client.Client(use_master=True)
            mocked_redis_cli.hset.side_effect = conn_err
            with self.assertRaises(q_exc.RedisConnectionFailure):
                client.apply_rules(port_id, mac_address.value, [])

    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_serialize_group_no_rules(self, strict_redis, conn_pool):
        client = redis_client.Client()
        group = models.SecurityGroup()
        payload = client.serialize_groups([group])
        self.assertEqual([], payload)

    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_serialize_group_with_rules(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 6, "port_range_min": 80,
                     "port_range_max": 443, "direction": "ingress"}
        client = redis_client.Client()
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
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_serialize_group_with_rules_and_remote_network(self, strict_redis,
                                                           conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 1, "direction": "ingress",
                     "remote_ip_prefix": "192.168.0.0/24"}
        client = redis_client.Client()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x800, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["port start"])
        self.assertEqual(None, rule["port end"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("::ffff:192.168.0.0/120", rule["source network"])
        self.assertEqual("", rule["destination network"])

    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_serialize_group_egress_rules(self, strict_redis, conn_pool):
        rule_dict = {"ethertype": 0x800, "protocol": 1,
                     "direction": "egress",
                     "remote_ip_prefix": "192.168.0.0/24"}
        client = redis_client.Client()
        group = models.SecurityGroup()
        rule = models.SecurityGroupRule()
        rule.update(rule_dict)
        group.rules.append(rule)

        payload = client.serialize_groups([group])
        rule = payload[0]
        self.assertEqual(0x800, rule["ethertype"])
        self.assertEqual(1, rule["protocol"])
        self.assertEqual(None, rule["port start"])
        self.assertEqual(None, rule["port end"])
        self.assertEqual("allow", rule["action"])
        self.assertEqual("ingress", rule["direction"])
        self.assertEqual("::ffff:192.168.0.0/120", rule["destination network"])
        self.assertEqual("", rule["source network"])


class TestRedisSentinelConnection(test_base.TestBase):
    def setUp(self):
        super(TestRedisSentinelConnection, self).setUp()
        # Forces the connection pool to be recreated on every test
        redis_client.Client.connection_pool = None

    @contextlib.contextmanager
    def _stubs(self, use_sentinels, sentinels, master_label):
        CONF.set_override("redis_use_sentinels", True, "QUARK")
        CONF.set_override("redis_sentinel_hosts", sentinels, "QUARK")
        CONF.set_override("redis_sentinel_master", master_label, "QUARK")
        yield
        CONF.set_override("redis_use_sentinels", False, "QUARK")
        CONF.set_override("redis_sentinel_hosts", '', "QUARK")
        CONF.set_override("redis_sentinel_master", '', "QUARK")

    @mock.patch("redis.sentinel.Sentinel")
    @mock.patch("redis.sentinel.SentinelConnectionPool")
    @mock.patch("redis.sentinel.Sentinel.master_for")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_sentinel_connection(self, strict_redis, master_for,
                                 sentinel_pool, sentinel_mock):
        host = "127.0.0.1"
        port = 6379
        sentinels = ["%s:%s" % (host, port)]
        master_label = "master"
        sentinel_mock.return_value = sentinels

        with self._stubs(True, sentinels, master_label):
            redis_client.Client(use_master=True)
            sentinel_pool.assert_called_with(master_label, sentinels,
                                             check_connection=True,
                                             is_master=True)

    @mock.patch("redis.sentinel.SentinelConnectionPool")
    @mock.patch("redis.sentinel.Sentinel.master_for")
    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_sentinel_connection_bad_format_raises(self, strict_redis,
                                                   master_for, sentinel_pool):
        sentinels = ""
        master_label = "master"

        with self._stubs(True, sentinels, master_label):
            with self.assertRaises(TypeError):
                redis_client.Client(is_master=True)


class TestRedisForAgent(test_base.TestBase):
    def setUp(self):
        super(TestRedisForAgent, self).setUp()

        patch = mock.patch("quark.security_groups.redis_client."
                           "redis.StrictRedis")
        self.MockSentinel = patch.start()
        self.addCleanup(patch.stop)

    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_get_security_groups_empty(self, strict_redis):
        mock_redis = mock.MagicMock()
        mock_pipeline = mock.MagicMock()
        strict_redis.return_value = mock_redis
        mock_redis.pipeline.return_value = mock_pipeline

        rc = redis_client.Client()
        group_uuids = rc.get_security_groups(set())
        mock_redis.pipeline.assert_called_once_with()
        self.assertEqual(mock_pipeline.get.call_count, 0)
        mock_pipeline.execute.assert_called_once_with()
        self.assertEqual(group_uuids, {})

    @mock.patch("quark.security_groups.redis_client.redis.StrictRedis")
    def test_get_security_groups_nonempty(self, strict_redis):
        mock_redis = mock.MagicMock()
        mock_pipeline = mock.MagicMock()
        strict_redis.return_value = mock_redis
        mock_redis.pipeline.return_value = mock_pipeline

        rc = redis_client.Client()

        mock_pipeline.execute.return_value = [
            None,
            '{}',
            '{"%s": null}' % redis_client.SECURITY_GROUP_VERSION_UUID_KEY,
            '{"%s": "1-2-3"}' % redis_client.SECURITY_GROUP_VERSION_UUID_KEY]

        new_interfaces = ([VIF(1, 2, 9), VIF(3, 4, 0), VIF(5, 6, 1),
                           VIF(7, 8, 2)])
        group_uuids = rc.get_security_groups(new_interfaces)
        mock_pipeline.hget.assert_has_calls(
            [mock.call("1.000000000002", "sg"),
             mock.call("3.000000000004", "sg"),
             mock.call("5.000000000006", "sg"),
             mock.call("7.000000000008", "sg")],
            any_order=True)
        mock_pipeline.execute.assert_called_once_with()
        self.assertEqual(group_uuids,
                         {VIF(1, 2, 9): None,
                          VIF(3, 4, 0): None,
                          VIF(5, 6, 1): None,
                          VIF(7, 8, 2): "1-2-3"})
