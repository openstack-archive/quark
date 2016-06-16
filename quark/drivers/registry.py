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

from quark.drivers import base
from quark.drivers import ironic_driver as ironic
from quark.drivers import optimized_nvp_driver as optnvp
from quark.drivers.registry_base import DriverRegistryBase
from quark.drivers import unmanaged

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class DriverRegistry(DriverRegistryBase):
    def __init__(self):
        super(DriverRegistry, self).__init__()

        self.drivers.update({
            base.BaseDriver.get_name(): base.BaseDriver(),
            optnvp.OptimizedNVPDriver.get_name(): optnvp.OptimizedNVPDriver(),
            unmanaged.UnmanagedDriver.get_name(): unmanaged.UnmanagedDriver(),
            ironic.IronicDriver.get_name(): ironic.IronicDriver()})

        # You may optionally specify a port-level driver name that will
        # be used intead of the underlying network driver. This map determines
        # which drivers are allowed to be used in this way.
        # example: {"MY_DRIVER": ["MY_OTHER_DRIVER"]}
        # The above example would allow ports created with "MY_DRIVER"
        # specified to be used with networks that use "MY_OTHER_DRIVER",
        # but *not* the inverse.
        # Note that drivers are automatically compatible with themselves.
        self.port_driver_compat_map = {
            ironic.IronicDriver.get_name(): [
                base.BaseDriver.get_name(),
                optnvp.OptimizedNVPDriver.get_name(),
                unmanaged.UnmanagedDriver.get_name()
            ]
        }

    def get_driver(self, net_driver, port_driver=None):
        LOG.info("Selecting driver for net_driver:%s "
                 "port_driver:%s" % (net_driver, port_driver))

        if port_driver:

            # Check port_driver is valid driver
            if port_driver not in self.drivers:
                raise Exception("Driver %s is not registered." % port_driver)

            # Net drivers are compatible with themselves
            if port_driver == net_driver:
                LOG.info("Selected port_driver:%s" % (port_driver))
                return self.drivers[port_driver]

            # Check port_driver is compatible with the given net_driver
            allowed = self.port_driver_compat_map.get(port_driver, [])
            if net_driver not in allowed:
                raise Exception("Port driver %s not allowed for "
                                "underlying network driver %s."
                                % (port_driver, net_driver))

            LOG.info("Selected port_driver:%s" % (port_driver))
            return self.drivers[port_driver]

        elif net_driver in self.drivers:
            LOG.info("Selected net_driver:%s" % (net_driver))
            return self.drivers[net_driver]

        raise Exception("Driver %s is not registered." % net_driver)

DRIVER_REGISTRY = DriverRegistry()
