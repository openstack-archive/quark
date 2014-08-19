# Copyright 2013 Openstack Foundation
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for# the specific language governing permissions and limitations
#  under the License.

from quark.db import api as db_api
from quark.tests.functional.base import BaseFunctionalTest


class QuarkFindPortsSorted(BaseFunctionalTest):
    def test_ports_sorted_by_created_at(self):
        # create a network
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        net_mod = db_api.network_create(self.context, **network)
        # create ports
        port1 = dict(network_id=net_mod["id"], backend_key="1", device_id="1")
        port2 = dict(network_id=net_mod["id"], backend_key="1", device_id="1")
        port3 = dict(network_id=net_mod["id"], backend_key="1", device_id="1")
        port_mod1 = db_api.port_create(self.context, **port1)
        port_mod2 = db_api.port_create(self.context, **port2)
        port_mod3 = db_api.port_create(self.context, **port3)
        res = db_api.port_find(self.context, scope=db_api.ALL)
        self.assertTrue(res[0]["created_at"] < res[1]["created_at"] <
                        res[2]['created_at'])
        db_api.network_delete(self.context, net_mod)
        db_api.port_delete(self.context, port_mod1)
        db_api.port_delete(self.context, port_mod2)
        db_api.port_delete(self.context, port_mod3)


class QuarkFindPortsFilterByDeviceOwner(BaseFunctionalTest):
    def test_port_list_device_owner_found_returns_only_those(self):
        # create a network
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        net_mod = db_api.network_create(self.context, **network)
        # create ports
        port1 = dict(network_id=net_mod["id"], backend_key="1", device_id="1",
                     device_owner="Doge")
        port2 = dict(network_id=net_mod["id"], backend_key="1", device_id="1",
                     device_owner=port1["device_owner"])
        port3 = dict(network_id=net_mod["id"], backend_key="1", device_id="1",
                     device_owner="network:dhcp")
        port_mod1 = db_api.port_create(self.context, **port1)
        port_mod2 = db_api.port_create(self.context, **port2)
        port_mod3 = db_api.port_create(self.context, **port3)
        res = db_api.port_find(self.context, scope=db_api.ALL,
                               device_owner=port3["device_owner"])
        self.assertTrue(len(res) == 1)
        self.assertTrue(res[0]["device_owner"] == port3["device_owner"])
        res = db_api.port_find(self.context, scope=db_api.ALL,
                               device_owner=port1["device_owner"])
        self.assertTrue(len(res) == 2)
        self.assertTrue(res[0]["device_owner"] == res[1]["device_owner"] ==
                        port1["device_owner"])
        db_api.network_delete(self.context, net_mod)
        db_api.port_delete(self.context, port_mod1)
        db_api.port_delete(self.context, port_mod2)
        db_api.port_delete(self.context, port_mod3)
