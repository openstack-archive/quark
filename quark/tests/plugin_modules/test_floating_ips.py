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

import contextlib

import mock

from quark.db import models
from quark import exceptions as quark_exceptions
from quark.tests import test_quark_plugin


class TestRemoveFloatingIPs(test_quark_plugin.TestQuarkPlugin):
    @contextlib.contextmanager
    def _stubs(self, addr):
        addr_model = None
        if addr:
            addr_model = models.IPAddress()
            addr_model.update(addr)

        with contextlib.nested(
            mock.patch("quark.db.api.floating_ip_find"),
            mock.patch("quark.ipam.QuarkIpam.deallocate_ip_address"),
            mock.patch("quark.drivers.unicorn_driver.UnicornDriver"
                       ".remove_floating_ip")
        ) as (flip_find, mock_dealloc, mock_remove_flip):
            flip_find.return_value = addr_model
            yield

    def test_delete_floating_by_ip_address_id(self):
        addr = dict(id=1, address=3232235876, address_readable="192.168.1.100",
                    subnet_id=1, network_id=2, version=4, used_by_tenant_id=1,
                    network=dict(ipam_strategy="ANY"))
        with self._stubs(addr=addr):
            self.plugin.delete_floatingip(self.context, 1)

    def test_delete_floating_by_when_ip_address_does_not_exists_fails(self):
        with self._stubs(addr=None):
            with self.assertRaises(quark_exceptions.FloatingIpNotFound):
                self.plugin.delete_floatingip(self.context, 1)
