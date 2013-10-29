# Copyright 2013 Openstack Foundation
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

from quark.drivers import base
from quark.drivers import optimized_nvp_driver as optnvp
from quark.drivers import unmanaged


class DriverRegistry(object):
    def __init__(self):
        self.drivers = {
            base.BaseDriver.get_name(): base.BaseDriver(),
            optnvp.OptimizedNVPDriver.get_name(): optnvp.OptimizedNVPDriver(),
            unmanaged.UnmanagedDriver.get_name(): unmanaged.UnmanagedDriver()}

    def get_driver(self, driver_name):
        if driver_name in self.drivers:
            return self.drivers[driver_name]
        raise Exception("Driver %s is not registered." % driver_name)


DRIVER_REGISTRY = DriverRegistry()
