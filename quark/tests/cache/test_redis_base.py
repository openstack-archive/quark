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
from oslo_config import cfg
import redis

from quark.cache import redis_base
from quark import exceptions as q_exc
from quark.tests import test_base

CONF = cfg.CONF


class TestClientBase(test_base.TestBase):

    def setUp(self):
        super(TestClientBase, self).setUp()
        # Forces the connection pool to be recreated on every test
        redis_base.ClientBase.read_connection_pool = None
        redis_base.ClientBase.write_connection_pool = None

    @mock.patch("quark.cache.redis_base.redis")
    def test_vif_key(self, *args, **kwargs):
        client = redis_base.ClientBase()
        device_id = str(uuid.uuid4())
        mac_address = netaddr.EUI("AA:BB:CC:DD:EE:FF")

        redis_key = client.vif_key(device_id, mac_address.value)
        expected = "%s.%s" % (device_id, "aabbccddeeff")
        self.assertEqual(expected, redis_key)

    @mock.patch("redis.ConnectionPool")
    @mock.patch("quark.cache.redis_base.redis.StrictRedis")
    def test_init(self, strict_redis, conn_pool):
        host = "127.0.0.1"
        port = 6379
        redis_base.ClientBase()
        conn_pool.assert_called_with(host=host, port=port)
        self.assertIsNotNone(redis_base.ClientBase.read_connection_pool)
        self.assertIsNotNone(redis_base.ClientBase.write_connection_pool)

    @mock.patch("redis.ConnectionPool")
    def test_client_connection_fails_gracefully(self, conn_pool):
        conn_err = redis.ConnectionError
        with mock.patch("redis.StrictRedis") as redis_mock:
            redis_mock.side_effect = conn_err
            with self.assertRaises(q_exc.RedisConnectionFailure):
                redis_base.ClientBase(use_master=True)

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_get_field(self, strict_redis):
        rc = redis_base.ClientBase()
        mock_client = rc._client = mock.MagicMock()
        mock_client.hget.return_value = "returned hash field"

        r = rc.get_field("1.000000000002", "test_field_name")

        mock_client.hget.assert_called_once_with("1.000000000002",
                                                 "test_field_name")

        self.assertEqual(r, "returned hash field")

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_vif_keys_hget(self, strict_redis):
        rc = redis_base.ClientBase()
        keys = ['1.000000000002', '2.000000000003']
        mock_client = rc._client = mock.MagicMock()
        mock_client.hget.return_value = "returned hash field"
        mock_client.keys.return_value = keys

        r = rc.vif_keys(field="test_field_name")

        mock_client.hget.assert_has_calls(
            [mock.call("1.000000000002", "test_field_name"),
             mock.call("2.000000000003", "test_field_name")])
        self.assertFalse(mock_client.hgetall.called)
        self.assertEqual(r, keys)

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_vif_keys_hget_string_key_returned(self, strict_redis):
        rc = redis_base.ClientBase()
        keys = '1.000000000002'
        mock_client = rc._client = mock.MagicMock()
        mock_client.hget.return_value = "returned hash field"
        mock_client.keys.return_value = keys

        r = rc.vif_keys(field="test_field_name")

        mock_client.hget.assert_called_once_with("1.000000000002",
                                                 "test_field_name")
        self.assertEqual(r, [keys])

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_vif_keys_hget_nil_returned(self, strict_redis):
        rc = redis_base.ClientBase()
        keys = ['1.000000000002', '2.000000000003']
        mock_client = rc._client = mock.MagicMock()
        mock_client.hget.side_effect = ["returned hash field", None]
        mock_client.keys.return_value = keys

        r = rc.vif_keys(field="test_field_name")

        mock_client.hget.assert_has_calls(
            [mock.call("1.000000000002", "test_field_name"),
             mock.call("2.000000000003", "test_field_name")])
        self.assertFalse(mock_client.hgetall.called)
        self.assertEqual(r, keys[:1])

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_vif_keys_hgetall(self, strict_redis):
        rc = redis_base.ClientBase()
        keys = ['1.000000000002', '2.000000000003']
        mock_client = rc._client = mock.MagicMock()
        mock_client.hgetall.return_value = {
            "returned hash field1": "returned hash value1",
            "returned hash field2": "returned hash value2"
        }
        mock_client.keys.return_value = keys

        r = rc.vif_keys()

        mock_client.hgetall.assert_has_calls([mock.call("1.000000000002"),
                                              mock.call("2.000000000003")])
        self.assertFalse(mock_client.hget.called)
        self.assertEqual(r, keys)

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_vif_keys_hgetall_nil_returned(self, strict_redis):
        rc = redis_base.ClientBase()
        keys = ['1.000000000002', '2.000000000003']
        mock_client = rc._client = mock.MagicMock()
        mock_client.hgetall.side_effect = [
            {
                "returned hash field1": "returned hash value1",
                "returned hash field2": "returned hash value2"
            },
            None
        ]
        mock_client.keys.return_value = keys

        r = rc.vif_keys()

        mock_client.hgetall.assert_has_calls([mock.call("1.000000000002"),
                                              mock.call("2.000000000003")])
        self.assertFalse(mock_client.hget.called)
        self.assertEqual(r, keys[:1])

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_set_field(self, strict_redis):
        rc = redis_base.ClientBase(use_master=True)
        mock_client = rc._client = mock.MagicMock()
        dummy_data = {"dummy_data": "foo"}

        rc.set_field("1.000000000002", "test_field_name", dummy_data)

        mock_client.hset.assert_called_once_with("1.000000000002",
                                                 "test_field_name",
                                                 json.dumps(dummy_data))

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_delete_field(self, strict_redis):
        rc = redis_base.ClientBase(use_master=True)
        mock_client = rc._client = mock.MagicMock()
        rc.delete_field("1.000000000002", "test_field_name")

        mock_client.hdel.assert_called_once_with("1.000000000002",
                                                 "test_field_name")

    @mock.patch(
        "quark.cache.redis_base.redis.StrictRedis")
    def test_get_fields(self, strict_redis):
        mock_redis = mock.MagicMock()
        mock_pipeline = mock.MagicMock()
        strict_redis.return_value = mock_redis
        mock_redis.pipeline.return_value = mock_pipeline
        mock_pipeline.execute.return_value = "returned executed"
        rc = redis_base.ClientBase()

        r = rc.get_fields(["1.000000000002", "1.000000000002",
                           "5.000000000006", "7.000000000008"],
                          "test_field_name")

        mock_pipeline.hget.assert_has_calls(
            [mock.call("1.000000000002", "test_field_name"),
             mock.call("1.000000000002", "test_field_name"),
             mock.call("5.000000000006", "test_field_name"),
             mock.call("7.000000000008", "test_field_name")],
            any_order=True)

        mock_pipeline.execute.assert_called_once_with()
        self.assertEqual(r, "returned executed")


class TestRedisSentinelConnection(test_base.TestBase):
    def setUp(self):
        super(TestRedisSentinelConnection, self).setUp()
        # Forces the connection pool to be recreated on every test
        redis_base.ClientBase.read_connection_pool = None
        redis_base.ClientBase.write_connection_pool = None

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
    @mock.patch("quark.cache.redis_base.redis.StrictRedis")
    def test_sentinel_connection(self, strict_redis, master_for,
                                 sentinel_pool, sentinel_mock):
        host = "127.0.0.1"
        port = 6379
        sentinels = ["%s:%s" % (host, port)]
        master_label = "master"
        sentinel_mock.return_value = sentinels

        with self._stubs(True, sentinels, master_label):
            redis_base.ClientBase(use_master=True)
            sentinel_pool.assert_called_with(master_label, sentinels,
                                             check_connection=True,
                                             is_master=True)

    @mock.patch("redis.sentinel.SentinelConnectionPool")
    @mock.patch("redis.sentinel.Sentinel.master_for")
    @mock.patch("quark.cache.redis_base.redis.StrictRedis")
    def test_sentinel_connection_bad_format_raises(self, strict_redis,
                                                   master_for, sentinel_pool):
        sentinels = ""
        master_label = "master"

        with self._stubs(True, sentinels, master_label):
            with self.assertRaises(TypeError):
                redis_base.ClientBase(is_master=True)
