# Copyright 2013 Rackspace Hosting Inc.
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

from neutron_lib import exceptions as n_exc

from quark.drivers import ironic_driver as ironic
from quark.drivers import optimized_nvp_driver as optnvp
from quark.drivers import registry
from quark.drivers import unmanaged
from quark.tests.functional.base import BaseFunctionalTest

from oslo_config import cfg


class TestDriverRegistry(BaseFunctionalTest):
    @contextlib.contextmanager
    def _stubs(self, enable_nvp=False, enable_ironic=False,
               enable_unmanaged=False):
        cfg.CONF.set_override('nvp', enable_nvp, 'enable_drivers')
        cfg.CONF.set_override('ironic', enable_ironic, 'enable_drivers')
        cfg.CONF.set_override('unmanaged', enable_unmanaged, 'enable_drivers')
        test_registry = registry.DRIVER_REGISTRY
        yield test_registry

    def test_get_nvp_driver(self):
        with self._stubs(enable_nvp=True) as test_reg:
            driver = test_reg.get_driver("NVP")
            self.assertIsInstance(driver, optnvp.OptimizedNVPDriver)

    def test_get_ironic_driver(self):
        with self._stubs(enable_ironic=True) as test_reg:
            driver = test_reg.get_driver("IRONIC")
            self.assertIsInstance(driver, ironic.IronicDriver)

    def test_get_unmanaged_driver(self):
        with self._stubs(enable_unmanaged=True) as test_reg:
            driver = test_reg.get_driver("UNMANAGED")
            self.assertIsInstance(driver, unmanaged.UnmanagedDriver)

    def test_get_nvp_driver_raises(self):
        with self._stubs() as test_reg:
            with self.assertRaises(n_exc.BadRequest):
                test_reg.get_driver("NVP")

    def test_get_ironic_driver_raises(self):
        with self._stubs() as test_reg:
            with self.assertRaises(n_exc.BadRequest):
                test_reg.get_driver("IRONIC")

    def test_get_unmanaged_driver_raises(self):
        with self._stubs() as test_reg:
            with self.assertRaises(n_exc.BadRequest):
                test_reg.get_driver("IRONIC")
