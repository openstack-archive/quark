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

import contextlib
from neutron import context
from neutron.db import api as neutron_db_api
from neutron.openstack.common.db.sqlalchemy import session as neutron_session
from oslo.config import cfg
import unittest2

from quark.db import api as db_api
from quark.db import models
import quark.ipam


class QuarkSubnetFunctionalTest(unittest2.TestCase):
    def setUp(self):
        self.context = context.Context('fake', 'fake', is_admin=False)
        super(QuarkSubnetFunctionalTest, self).setUp()

        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        neutron_db_api.configure_db()
        models.BASEV2.metadata.create_all(neutron_session._ENGINE)

    def tearDown(self):
        neutron_db_api.clear_db()


class QuarkGetSubnets(QuarkSubnetFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, network, subnet):
        self.ipam = quark.ipam.QuarkIpamANY()
        with self.context.session.begin():
            net_mod = db_api.network_create(self.context, **network)
            subnet["network"] = net_mod
            sub1 = db_api.subnet_create(self.context, **subnet)
            subnet["id"] = 2
            sub2 = db_api.subnet_create(self.context, do_not_use=True,
                                        **subnet)
        yield net_mod, sub1, sub2

    def test_get_subnet_do_not_use_not_returned(self):
        network = dict(name="public", tenant_id="fake", network_plugin="BASE")
        subnet = dict(id=1, ip_version=4, next_auto_assign_ip=2,
                      cidr="0.0.0.0/24", first_ip=0, last_ip=255,
                      ip_policy=None, tenant_id="fake")
        with self._stubs(network, subnet) as (net, sub1, sub2):
            subnets = db_api.subnet_find_allocation_counts(self.context,
                                                           net["id"]).all()
            self.assertEqual(len(subnets), 1)
            self.assertEqual(subnets[0][0]["id"], "1")
