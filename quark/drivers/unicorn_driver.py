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
import netaddr
import requests

from oslo.config import cfg
from oslo_log import log as logging

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

        if r.status_code != 200:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("register_floating_ip: %s" % msg)
            raise ex.RegisterFloatingIpFailure(id=floating_ip.id)

    def update_floating_ip(self, floating_ip):
        pass

    def remove_floating_ip(self, floating_ip):
        url = "%s/%s" % (CONF.QUARK.floating_ip_base_url,
                         floating_ip.address_readable)

        LOG.info("Calling unicorn to remove floating ip: %s" % url)
        r = requests.delete(url)

        if r.status_code != 204:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("remove_floating_ip: %s" % msg)
            raise ex.RemoveFloatingIpFailure(id=floating_ip.id)

    @staticmethod
    def _build_request_body(floating_ip, port, fixed_ip):
        mac_addr = netaddr.EUI(port.mac_address)
        content = {"public_ip": floating_ip["address_readable"],
                   "network_uuid": port.id,
                   "destinations": [
                       {"private_ip": fixed_ip.address_readable,
                        "private_mac": str(mac_addr)}]}
        return {"floating_ip": content}
