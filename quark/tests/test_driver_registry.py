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

from quark.drivers import registry
from quark.drivers import registry_base
from quark.tests import test_base


class FakeBaseRegistry(registry_base.DriverRegistryBase):

    def __init__(self):
        self.drivers = {"test_driver_1": 1,
                        "test_driver_2": 2}


class FakeNetDriverRegistry(registry.DriverRegistry):

    def __init__(self):
        self.drivers = {"test_driver_1": 1,
                        "test_driver_2": 2,
                        "test_driver_3": 3}

        self.port_driver_compat_map = {
            "test_driver_2": ["test_driver_1"],
            "test_driver_3": ["test_driver_1",
                              "test_driver_2"]
        }


class TestRegistryBase(test_base.TestBase):

    def setUp(self):
        self.registry = FakeBaseRegistry()

    def test_get_valid(self):
        driver = self.registry.get_driver("test_driver_1")
        self.assertEqual(driver, 1)

        driver = self.registry.get_driver("test_driver_2")
        self.assertEqual(driver, 2)

    def test_get_invalid(self):
        exc = "Driver does_not_exist is not registered."
        with self.assertRaisesRegexp(Exception, exc):
            self.registry.get_driver("does_not_exist")


class TestDriverRegistry(TestRegistryBase):

    def setUp(self):
        self.registry = FakeNetDriverRegistry()

    def test_get_port_driver(self):
        driver = self.registry.get_driver(
            "test_driver_1", port_driver="test_driver_1")
        self.assertEqual(driver, 1)

        driver = self.registry.get_driver(
            "test_driver_2", port_driver="test_driver_2")
        self.assertEqual(driver, 2)

    def test_get_invalid_port_driver(self):
        exc = "Driver does_not_exist is not registered."
        with self.assertRaisesRegexp(Exception, exc):
            self.registry.get_driver(
                "test_driver_1", port_driver="does_not_exist")

    def test_get_compatable_port_driver(self):
        driver = self.registry.get_driver(
            "test_driver_1", port_driver="test_driver_2")
        self.assertEqual(driver, 2)

        driver = self.registry.get_driver(
            "test_driver_1", port_driver="test_driver_3")
        self.assertEqual(driver, 3)

        driver = self.registry.get_driver(
            "test_driver_2", port_driver="test_driver_3")
        self.assertEqual(driver, 3)

    def test_get_incompatable_port_driver(self):
        exc = ("Port driver test_driver_2 not allowed for "
               "underlying network driver test_driver_3.")
        with self.assertRaisesRegexp(Exception, exc):
            self.registry.get_driver(
                "test_driver_3", port_driver="test_driver_2")
