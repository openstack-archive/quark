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

import mock

from quark.agent import agent
from quark.agent import xapi
from quark.tests import test_base


class TestAgentPartitionVifs(test_base.TestBase):
    @mock.patch("quark.agent.xapi.XapiClient._session")
    def test_partition_vifs(self, sess):
        def _vif_rec(mac, tagged):
            rec = {"MAC": mac, "other_config": {}}
            if tagged:
                rec["other_config"] = {"security_groups": "enabled"}
            return rec

        vif_recs = [_vif_rec(1, False), _vif_rec(2, True), _vif_rec(3, True),
                    _vif_rec(4, False), _vif_rec(5, False)]

        interfaces = [xapi.VIF("added", vif_recs[0], "added_ref"),
                      xapi.VIF("updated", vif_recs[1], "updated_ref"),
                      xapi.VIF("removed", vif_recs[2], "removed_ref"),
                      xapi.VIF("no groups", vif_recs[3], "no groups ref"),
                      xapi.VIF("self heal", vif_recs[4], "self heal ref")]

        sg_states = {interfaces[0]: False, interfaces[1]: False,
                     interfaces[4]: True}

        xapi_client = xapi.XapiClient()

        added, updated, removed = agent.partition_vifs(xapi_client,
                                                       interfaces,
                                                       sg_states)

        self.assertEqual(added, [interfaces[0], interfaces[4]])
        self.assertEqual(updated, [interfaces[1]])
        self.assertEqual(removed, [interfaces[2]])
