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
    @mock.patch("quark.agent.xapi.XapiClient.is_vif_tagged")
    def test_partition_vifs(self, is_vif_tagged, sess):
        interfaces = [xapi.VIF("added", 1, "added_ref"),
                      xapi.VIF("updated", 2, "updated_ref"),
                      xapi.VIF("removed", 3, "removed_ref"),
                      xapi.VIF("no groups", 4, "no groups ref"),
                      xapi.VIF("not found", 5, "not found ref"),
                      xapi.VIF("self heal", 6, "self heal ref")]

        sg_states = {interfaces[0]: False, interfaces[1]: False,
                     interfaces[5]: True}

        xapi_client = xapi.XapiClient()
        is_vif_tagged.side_effect = [False, True, True, False, None,
                                     False]

        added, updated, removed = agent.partition_vifs(xapi_client,
                                                       interfaces,
                                                       sg_states)

        self.assertEqual(added, [interfaces[0], interfaces[5]])
        self.assertEqual(updated, [interfaces[1]])
        self.assertEqual(removed, [interfaces[2]])
