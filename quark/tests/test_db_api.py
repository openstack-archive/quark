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
# License for the specific language governing permissions and limitations
#  under the License.

import mock
from oslo.config import cfg
from quantum.db import api as quantum_db_api

from quark.db import api as db_api

from quark.tests import test_base

from sqlalchemy.orm import configure_mappers


class TestDBAPI(test_base.TestBase):
    def setUp(self):
        super(TestDBAPI, self).setUp()

        cfg.CONF.set_override('connection', 'sqlite://', 'database')
        quantum_db_api.configure_db()
        configure_mappers()

    def test_port_find_ip_address_id(self):
        self.context.session.query = mock.Mock()
        db_api.port_find(self.context, ip_address_id="fake")
        query_obj = self.context.session.query.return_value
        filter_fn = query_obj.options.return_value.filter
        self.assertEqual(filter_fn.call_count, 1)

    def test_ip_address_find_device_id(self):
        self.context.session.query = mock.Mock()
        db_api.ip_address_find(self.context, device_id="foo")
        query_obj = self.context.session.query.return_value
        filter_fn = query_obj.filter
        self.assertEqual(filter_fn.call_count, 1)
