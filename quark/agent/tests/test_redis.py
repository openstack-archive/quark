import mock

from quark.agent import redis_client as redis
from quark.agent.xapi import VIF
from quark.tests import test_base


class TestRedisClient(test_base.TestBase):
    def setUp(self):
        super(TestRedisClient, self).setUp()

        patch = mock.patch("quark.agent.redis_client.Sentinel")
        self.MockSentinel = patch.start()
        self.addCleanup(patch.stop)

    def test_get_security_groups_empty(self):
        rc = redis.RedisClient()

        sentinel = self.MockSentinel.return_value
        slave = sentinel.slave_for.return_value
        pipeline = slave.pipeline.return_value
        pipeline.execute.return_value = []

        group_uuids = rc.get_security_groups(set())
        self.assertEqual(pipeline.get.call_count, 0)
        pipeline.execute.assert_called_once_with()
        self.assertEqual(group_uuids, {})

    def test_get_security_groups_nonempty(self):
        rc = redis.RedisClient()

        sentinel = self.MockSentinel.return_value
        slave = sentinel.slave_for.return_value
        pipeline = slave.pipeline.return_value
        pipeline.execute.return_value = [
            None,
            '{}',
            '{"%s": null}' % redis.SECURITY_GROUP_VERSION_UUID_KEY,
            '{"%s": "1-2-3"}' % redis.SECURITY_GROUP_VERSION_UUID_KEY]

        new_interfaces = ([VIF(1, 2), VIF(3, 4), VIF(5, 6), VIF(7, 8)])
        group_uuids = rc.get_security_groups(new_interfaces)
        pipeline.get.assert_has_calls(
            [mock.call("1.2"),
             mock.call("3.4"),
             mock.call("5.6"),
             mock.call("7.8")],
            any_order=True)
        pipeline.execute.assert_called_once_with()
        self.assertEqual(group_uuids,
                         {VIF(1, 2): None,
                          VIF(3, 4): None,
                          VIF(5, 6): None,
                          VIF(7, 8): "1-2-3"})
