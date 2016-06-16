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

from oslo_config import cfg

from quark.drivers.registry import DriverRegistryBase
from quark.drivers import unicorn_driver as unicorn

CONF = cfg.CONF

quark_router_opts = [
    cfg.StrOpt('default_floating_ip_driver',
               default='Unicorn',
               help=_('Driver for floating IP')),
]

CONF.register_opts(quark_router_opts, 'QUARK')


class FloatingIPDriverRegistry(DriverRegistryBase):
    def __init__(self):
        self.drivers = {
            unicorn.UnicornDriver.get_name(): unicorn.UnicornDriver()}

    def get_driver(self, driver_name=None):
        if not driver_name:
            driver_name = CONF.QUARK.default_floating_ip_driver

        if driver_name in self.drivers:
            return self.drivers[driver_name]

        raise Exception("Driver %s is not registered." % driver_name)

DRIVER_REGISTRY = FloatingIPDriverRegistry()
