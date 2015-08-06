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

"""
Unicorn driver for Quark
"""

import json
import requests

from oslo_config import cfg
from oslo_log import log as logging

from quark.db import ip_types
from quark import exceptions as ex

CONF = cfg.CONF
LOG = logging.getLogger(__name__)

quark_router_opts = [
    cfg.StrOpt('floating_ip_base_url',
               default='http://localhost:8080/v1.0/floating_ips',
               help=_('floating ips base url'))
]

CONF.register_opts(quark_router_opts, "QUARK")


class UnicornDriver(object):
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        return "Unicorn"

    def register_floating_ip(self, floating_ip, port, fixed_ip):
        url = CONF.QUARK.floating_ip_base_url
        req = self._build_request_body(floating_ip, port, fixed_ip)

        LOG.info("Calling unicorn to register floating ip: %s %s" % (url, req))
        r = requests.post(url, data=json.dumps(req))

        if r.status_code != 200 and r.status_code != 201:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("register_floating_ip: %s" % msg)
            raise ex.RegisterFloatingIpFailure(id=floating_ip.id)

    def update_floating_ip(self, floating_ip, port, fixed_ip):
        url = "%s/%s" % (CONF.QUARK.floating_ip_base_url,
                         floating_ip["address_readable"])
        req = self._build_request_body(floating_ip, port, fixed_ip)

        LOG.info("Calling unicorn to register floating ip: %s %s" % (url, req))
        r = requests.put(url, data=json.dumps(req))

        if r.status_code != 200 and r.status_code != 201:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("register_floating_ip: %s" % msg)
            raise ex.RegisterFloatingIpFailure(id=floating_ip.id)

    def remove_floating_ip(self, floating_ip):
        url = "%s/%s" % (CONF.QUARK.floating_ip_base_url,
                         floating_ip.address_readable)

        LOG.info("Calling unicorn to remove floating ip: %s" % url)
        r = requests.delete(url)

        if r.status_code == 404:
            LOG.warn("The floating IP %s does not exist in the unicorn system."
                     % floating_ip.address_readable)
        elif r.status_code != 204:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("remove_floating_ip: %s" % msg)
            raise ex.RemoveFloatingIpFailure(id=floating_ip.id)

    @staticmethod
    def _build_request_body(floating_ip, port, fixed_ip):
        fixed_ips = [{"ip_address": ip.address_readable,
                      "version": ip.version,
                      "subnet_id": ip.subnet.id,
                      "cidr": ip.subnet.cidr,
                      "address_type": ip.address_type}
                     for ip in port.ip_addresses
                     if (ip.get("address_type") == ip_types.FIXED)]
        content = {"public_ip": floating_ip["address_readable"],
                   "endpoints": [
                       {"port": {"uuid": port.id,
                                 "name": port.name,
                                 "network_uuid": port.network_id,
                                 "mac_address": port.mac_address,
                                 "device_id": port.device_id,
                                 "device_owner": port.device_owner,
                                 "fixed_ip": fixed_ips},
                        "private_ip": fixed_ip.address_readable}]}
        return {"floating_ip": content}
