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
#

import contextlib
import mock

from quark.agent import agent
from quark.agent import xapi
from quark.cache import security_groups_client as sg
from quark.tests import test_base


class TestAgentPartitionVifs(test_base.TestBase):
    def setUp(self):
        self.vif_recs = [self._vif_rec(1, False), self._vif_rec(2, True),
                         self._vif_rec(3, True), self._vif_rec(4, False),
                         self._vif_rec(5, False)]
        self.interfaces = [xapi.VIF("added", self.vif_recs[0], "added_ref"),
                           xapi.VIF("updated", self.vif_recs[1],
                                    "updated_ref"),
                           xapi.VIF("removed", self.vif_recs[2],
                                    "removed_ref"),
                           xapi.VIF("no groups", self.vif_recs[3],
                                    "no groups ref"),
                           xapi.VIF("self heal", self.vif_recs[4],
                                    "self heal ref")]
        self.ack = sg.SECURITY_GROUP_ACK
        self.rules = sg.SECURITY_GROUP_HASH_ATTR
        self.sg_states = {self.interfaces[0]: {self.ack: False,
                                               self.rules: []},
                          self.interfaces[1]: {self.ack: False,
                                               self.rules: []},
                          self.interfaces[4]: {self.ack: True,
                                               self.rules: []}}
        self.client = sg.SecurityGroupsClient()

    @contextlib.contextmanager
    def _stubs(self, interfaces, sg_states, vif_recs):
        with mock.patch("quark.cache.security_groups_client."
                        "SecurityGroupsClient.get_security_group_states")\
                as sec_grp_client,\
                mock.patch("quark.agent.xapi.XapiClient._session"):
            sec_grp_client.side_effect = sg_states
            yield interfaces, sg_states, vif_recs

    def _vif_rec(self, mac, tagged):
        rec = {"MAC": mac, "other_config": {}}
        if tagged:
            rec["other_config"] = {"security_groups": "enabled"}
        return rec

    def test_partition_vifs(self):
        with self._stubs(self.interfaces, self.sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            xapi_client = xapi.XapiClient()
            added, updated, removed = agent.partition_vifs(xapi_client,
                                                           interfaces,
                                                           sg_states)
            self.assertEqual(added, [interfaces[0], interfaces[4]])
            self.assertEqual(updated, [interfaces[1]])
            self.assertEqual(removed, [interfaces[2]])

    def test_get_groups_to_ack_rule_mismatch_init_empty(self):
        sg_states = [
            {self.interfaces[0]: {self.ack: False, self.rules: []}},
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"}]}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual([], gta)

    def test_get_groups_to_ack_rule_mismatch_init_populated(self):
        sg_states = [
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"}]}},
            {self.interfaces[0]: {self.ack: False, self.rules: []}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual([], gta)

    def test_get_groups_to_ack_rule_mismatch_both_populated(self):
        sg_states = [
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"}]}},
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blech": "blah"}]}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual([], gta)

    def test_get_groups_to_ack_rule_mismatch_both_populated_multi(self):
        sg_states = [
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"},
                                   {"blech": "blah"}]}},
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blech": "blah"}]}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual([], gta)

        sg_states = [
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blech": "blah"}]}},
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"},
                                   {"blech": "blah"}]}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual([], gta)

    def test_get_groups_to_ack_rule_match_both_empty(self):
        sg_states = [{self.interfaces[0]: {self.ack: False, self.rules: []}},
                     {self.interfaces[0]: {self.ack: False, self.rules: []}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            self.assertEqual(curr_grps, init_grps)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual(groups_to_ack, gta)

    def test_get_groups_to_ack_rule_match_both_populated(self):
        sg_states = [
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"}]}},
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"}]}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            self.assertEqual(curr_grps, init_grps)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual(groups_to_ack, gta)

    def test_get_groups_to_ack_rule_match_both_populated_multi(self):
        sg_states = [
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blah": "blech"},
                                   {"blech": "blah"}]}},
            {self.interfaces[0]: {self.ack: False, self.rules:
                                  [{"blech": "blah"},
                                   {"blah": "blech"}]}}]
        with self._stubs(self.interfaces, sg_states, self.vif_recs)\
                as (interfaces, sg_states, vif_recs):
            init_grps = self.client.get_security_group_states(interfaces)
            groups_to_ack = [self.interfaces[0]]
            curr_grps = self.client.get_security_group_states(interfaces)
            gta = agent.get_groups_to_ack(groups_to_ack, init_grps, curr_grps)
            self.assertEqual(groups_to_ack, gta)
