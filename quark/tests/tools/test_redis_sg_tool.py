#!/usr/bin/python
# Copyright 2015 Rackspace Hosting
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
#    under the License.


import contextlib

import mock

from quark.cache import security_groups_client
from quark.db import models
from quark import exceptions as q_exc
from quark.tests import test_base
from quark.tools import redis_sg_tool

TOOL_MOD = "quark.tools.redis_sg_tool.QuarkRedisTool"


def sg_client(args=None):
    args = args or {}
    return redis_sg_tool.QuarkRedisTool(args)


class QuarkRedisSgToolBase(test_base.TestBase):
    def setUp(self):
        super(QuarkRedisSgToolBase, self).setUp()
        neutron_cfg_patch = mock.patch("neutron.common.config.init")
        oslo_cfg_patch = mock.patch("oslo_config.cfg.CONF")
        neutron_cfg_patch.start()
        oslo_cfg_patch.start()
        self.addCleanup(neutron_cfg_patch.stop)
        self.addCleanup(oslo_cfg_patch.stop)


class QuarkRedisSgToolTestDispatch(QuarkRedisSgToolBase):
    def _client_dispatch(self, command):
        args = {"<command>": command}
        sg_client(args).dispatch()

    @mock.patch("%s.test_connection" % TOOL_MOD)
    def test_dispatch_test_connection(self, test_conn):
        self._client_dispatch("test-connection")
        test_conn.assert_called_with()

    @mock.patch("%s.vif_count" % TOOL_MOD)
    def test_dispatch_vifs_in_redis(self, vif_count):
        self._client_dispatch("vifs-in-redis")
        vif_count.assert_called_with()

    @mock.patch("%s.num_groups" % TOOL_MOD)
    def test_dispatch_num_groups(self, num_groups):
        self._client_dispatch("num-groups")
        num_groups.assert_called_with()

    @mock.patch("%s.ports_with_groups" % TOOL_MOD)
    def test_dispatch_ports_with_groups(self, ports_with_groups):
        self._client_dispatch("ports-with-groups")
        ports_with_groups.assert_called_with()

    @mock.patch("%s.purge_orphans" % TOOL_MOD)
    def test_dispatch_purge_orphans(self, purge_orphans):
        self._client_dispatch("purge-orphans")
        purge_orphans.assert_called_with(True)

    @mock.patch("%s.write_groups" % TOOL_MOD)
    def test_dispatch_write_groups(self, write_groups):
        self._client_dispatch("write-groups")
        write_groups.assert_called_with(True)

    @mock.patch("%s.test_connection" % TOOL_MOD)
    @mock.patch("%s.vif_count" % TOOL_MOD)
    @mock.patch("%s.num_groups" % TOOL_MOD)
    @mock.patch("%s.ports_with_groups" % TOOL_MOD)
    @mock.patch("%s.purge_orphans" % TOOL_MOD)
    @mock.patch("%s.write_groups" % TOOL_MOD)
    def test_dispatch_nothing(self, write_groups, purge_orphans,
                              ports_with_groups, num_groups, vif_count,
                              test_conn):
        self._client_dispatch("Nothing")
        self.assertFalse(write_groups.called)
        self.assertFalse(purge_orphans.called)
        self.assertFalse(ports_with_groups.called)
        self.assertFalse(num_groups.called)
        self.assertFalse(vif_count.called)
        self.assertFalse(test_conn.called)


class QuarkRedisSgToolTestConnection(QuarkRedisSgToolBase):
    @mock.patch("%s._get_connection" % TOOL_MOD)
    def test_connected(self, get_conn):
        get_conn.return_value = True
        cli = sg_client()
        self.assertTrue(cli.test_connection())

    @mock.patch("%s._get_connection" % TOOL_MOD)
    def test_not_connected(self, get_conn):
        get_conn.return_value = False
        cli = sg_client()
        self.assertFalse(cli.test_connection())


class QuarkRedisSgToolVifCount(QuarkRedisSgToolBase):
    @mock.patch("%s._get_connection" % TOOL_MOD)
    def test_vif_count(self, get_conn):
        conn_mock = mock.MagicMock()
        get_conn.return_value = conn_mock
        cli = sg_client()
        cli.vif_count()
        conn_mock.vif_keys.assert_called_with(
            field=security_groups_client.SECURITY_GROUP_HASH_ATTR)


class QuarkRedisSgToolNumGroups(QuarkRedisSgToolBase):
    @mock.patch("neutron.context.get_admin_context")
    @mock.patch("quark.db.api.security_group_count")
    def test_num_groups(self, group_count, get_admin_ctxt):
        ctxt_mock = mock.MagicMock()
        get_admin_ctxt.return_value = ctxt_mock

        cli = sg_client()
        cli.num_groups()
        group_count.assert_called_with(ctxt_mock)


class QuarkRedisSgToolPortsWithGroups(QuarkRedisSgToolBase):
    @mock.patch("neutron.context.get_admin_context")
    @mock.patch("quark.db.api.ports_with_security_groups_count")
    def test_num_groups(self, db_ports_groups, get_admin_ctxt):
        db_ports_groups.return_value = mock.MagicMock()
        ctxt_mock = mock.MagicMock()
        get_admin_ctxt.return_value = ctxt_mock

        cli = sg_client()
        cli.ports_with_groups()
        db_ports_groups.assert_called_with(ctxt_mock)


class QuarkRedisSgToolPurgeOrphans(QuarkRedisSgToolBase):
    @contextlib.contextmanager
    def _stubs(self):
        ports = [{"device_id": 1, "mac_address": 1}]
        vifs = ["1.1", "2.2", "3.3"]
        with contextlib.nested(
            mock.patch("neutron.context.get_admin_context"),
            mock.patch("quark.db.api.ports_with_security_groups_find"),
            mock.patch("%s._get_connection" % TOOL_MOD)
        ) as (get_admin_ctxt, db_ports_groups, get_conn):
            connection_mock = mock.MagicMock()
            get_conn.return_value = connection_mock
            ports_with_groups_mock = mock.MagicMock()
            db_ports_groups.return_value = ports_with_groups_mock
            ctxt_mock = mock.MagicMock()
            get_admin_ctxt.return_value = ctxt_mock
            ports_with_groups_mock.all.return_value = ports
            connection_mock.vif_keys.return_value = vifs
            yield get_conn, connection_mock, db_ports_groups, ctxt_mock

    def test_purge_orphans_dry_run(self):
        with self._stubs() as (get_conn, connection_mock, db_ports_groups,
                               ctxt_mock):
            cli = sg_client()
            cli.purge_orphans(dryrun=True)

            connection_mock.vif_key.assert_any_call(1, 1)
            db_ports_groups.assert_called_with(ctxt_mock)
            connection_mock.delete_key.assert_not_called()
            self.assertTrue(get_conn.call_count, 1)

    def test_purge_orphans(self):
        with self._stubs() as (get_conn, connection_mock, db_ports_groups,
                               ctxt_mock):
            cli = sg_client()
            cli.purge_orphans(dryrun=False)

            db_ports_groups.assert_called_with(ctxt_mock)
            connection_mock.vif_key.assert_any_call(1, 1)
            connection_mock.delete_key.assert_any_call("2.2")
            connection_mock.delete_key.assert_any_call("3.3")

    @mock.patch("time.sleep")
    def test_purge_orphans_raises(self, sleep):
        retry_delay = 1
        retries = 1
        with self._stubs() as (get_conn, connection_mock, db_ports_groups,
                               ctxt_mock):
            redis_exc = q_exc.RedisConnectionFailure
            connection_mock.delete_key.side_effect = redis_exc
            cli = sg_client({"--retry-delay": retry_delay,
                             "--retries": retries})
            cli.purge_orphans(dryrun=False)

            db_ports_groups.assert_called_with(ctxt_mock)
            get_conn.assert_called_with(giveup=False)
            connection_mock.vif_key.assert_any_call(1, 1)
            connection_mock.delete_key.assert_any_call("2.2")
            connection_mock.delete_key.assert_any_call("3.3")
            sleep.assert_called_with(1)


class QuarkRedisSgToolWriteGroups(QuarkRedisSgToolBase):
    @contextlib.contextmanager
    def _stubs(self):
        ports = [{"device_id": 1, "mac_address": 1}]
        vifs = ["1.1", "2.2", "3.3"]
        security_groups = [{"id": 1, "name": "test_group"}]

        with contextlib.nested(
            mock.patch("neutron.context.get_admin_context"),
            mock.patch("quark.db.api.security_group_rule_find"),
            mock.patch("quark.db.api.ports_with_security_groups_find"),
            mock.patch("%s._get_connection" % TOOL_MOD)
        ) as (get_admin_ctxt, rule_find, db_ports_groups, get_conn):
            connection_mock = mock.MagicMock()
            get_conn.return_value = connection_mock
            ports_with_groups_mock = mock.MagicMock()

            port_mods = []
            sg_mods = [models.SecurityGroup(**sg) for sg in security_groups]
            for port in ports:
                port_mod = models.Port(**port)
                port_mod.security_groups = sg_mods
                port_mods.append(port_mod)

            sg_rule = models.SecurityGroupRule()
            rule_find.return_value = [sg_rule]

            db_ports_groups.return_value = ports_with_groups_mock
            ctxt_mock = mock.MagicMock()
            get_admin_ctxt.return_value = ctxt_mock
            ports_with_groups_mock.all.return_value = port_mods
            connection_mock.vif_keys.return_value = vifs
            connection_mock.serialize_rules.return_value = "rules"
            yield (get_conn, connection_mock, db_ports_groups, ctxt_mock,
                   sg_rule)

    def test_write_groups_dryrun(self):
        with self._stubs() as (get_conn, connection_mock, db_ports_groups,
                               ctxt_mock, sg_rule):
            cli = sg_client()
            cli.write_groups(dryrun=True)
            connection_mock.vif_keys.assert_called_with()
            connection_mock.get_rules_for_port.assert_called_with(1, 1)

            self.assertTrue(get_conn.call_count, 1)

    def test_write_groups(self):
        with self._stubs() as (get_conn, connection_mock, db_ports_groups,
                               ctxt_mock, sg_rule):
            cli = sg_client()
            cli.write_groups(dryrun=False)
            self.assertFalse(connection_mock.vif_keys.called)
            self.assertFalse(connection_mock.get_rules_for_port.called)
            self.assertFalse(connection_mock.get_rules_for_port.called)
            connection_mock.serialize_rules.assert_called_with([sg_rule])
            connection_mock.apply_rules.assert_called_with(1, 1, "rules")

            self.assertTrue(get_conn.call_count, 1)

    @mock.patch("time.sleep")
    def test_write_groups_raises(self, sleep):
        with self._stubs() as (get_conn, connection_mock, db_ports_groups,
                               ctxt_mock, sg_rule):
            retry_delay = 1
            retries = 1
            cli = sg_client({"--retry-delay": retry_delay,
                             "--retries": retries})
            redis_exc = q_exc.RedisConnectionFailure
            connection_mock.apply_rules.side_effect = redis_exc

            cli.write_groups(dryrun=False)
            self.assertFalse(connection_mock.vif_keys.called)
            self.assertFalse(connection_mock.get_rules_for_port.called)
            self.assertFalse(connection_mock.get_rules_for_port.called)
            connection_mock.serialize_rules.assert_called_with([sg_rule])
            sleep.assert_called_with(1)
            self.assertTrue(get_conn.call_count, 2)
            get_conn.assert_any_call(giveup=False)
