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
               help=_('floating ips base url')),
    cfg.IntOpt('unicorn_api_timeout_seconds', default=2,
               help=_('Number of seconds to wait for a response from the '
                      'server before failing the call'))
]

CONF.register_opts(quark_router_opts, "QUARK")


class UnicornDriver(object):
    def __init__(self):
        pass

    @classmethod
    def get_name(cls):
        return "Unicorn"

    def register_floating_ip(self, floating_ip, port_fixed_ips):
        """Register a floating ip with Unicorn

        :param floating_ip: The quark.db.models.IPAddress to register
        :param port_fixed_ips: A dictionary containing the port and fixed ips
        to associate the floating IP with.  Has the structure of:
        {"<id of port>": {"port": <quark.db.models.Port>,
         "fixed_ip": "<fixed ip address>"}}
        :return: None
        """
        url = CONF.QUARK.floating_ip_base_url
        timeout = CONF.QUARK.unicorn_api_timeout_seconds
        req = self._build_request_body(floating_ip, port_fixed_ips)

        try:
            LOG.info("Calling unicorn to register floating ip: %s %s"
                     % (url, req))
            r = requests.post(url, data=json.dumps(req), timeout=timeout)
        except Exception as e:
            LOG.error("Unhandled Exception caught when trying to register "
                      "floating ip %s with the unicorn API.  Error: %s"
                      % (floating_ip.id, e.message))
            raise ex.RegisterFloatingIpFailure(id=floating_ip.id)

        if r.status_code != 200 and r.status_code != 201:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("register_floating_ip: %s" % msg)
            raise ex.RegisterFloatingIpFailure(id=floating_ip.id)

    def update_floating_ip(self, floating_ip, port_fixed_ips):
        """Update an existing floating ip with Unicorn

        :param floating_ip: The quark.db.models.IPAddress to update
        :param port_fixed_ips: A dictionary containing the port and fixed ips
        to associate the floating IP with.  Has the structure of:
        {"<id of port>": {"port": <quark.db.models.Port>,
         "fixed_ip": "<fixed ip address>"}}
        :return: None
        """
        url = "%s/%s" % (CONF.QUARK.floating_ip_base_url,
                         floating_ip["address_readable"])
        timeout = CONF.QUARK.unicorn_api_timeout_seconds
        req = self._build_request_body(floating_ip, port_fixed_ips)

        try:
            LOG.info("Calling unicorn to update floating ip: %s %s"
                     % (url, req))
            r = requests.put(url, data=json.dumps(req), timeout=timeout)
        except Exception as e:
            LOG.error("Unhandled Exception caught when trying to update "
                      "floating ip %s with the unicorn API.  Error: %s"
                      % (floating_ip.id, e.message))
            raise ex.RegisterFloatingIpFailure(id=floating_ip.id)

        if r.status_code != 200 and r.status_code != 201:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("register_floating_ip: %s" % msg)
            raise ex.RegisterFloatingIpFailure(id=floating_ip.id)

    def remove_floating_ip(self, floating_ip):
        """Register a floating ip with Unicorn

        :param floating_ip: The quark.db.models.IPAddress to remove
        :return: None
        """
        url = "%s/%s" % (CONF.QUARK.floating_ip_base_url,
                         floating_ip.address_readable)
        timeout = CONF.QUARK.unicorn_api_timeout_seconds

        try:
            LOG.info("Calling unicorn to remove floating ip: %s" % url)
            r = requests.delete(url, timeout=timeout)
        except Exception as e:
            LOG.error("Unhandled Exception caught when trying to un-register "
                      "floating ip %s with the unicorn API.  Error: %s"
                      % (floating_ip.id, e.message))
            raise ex.RemoveFloatingIpFailure(id=floating_ip.id)

        if r.status_code == 404:
            LOG.warn("The floating IP %s does not exist in the unicorn system."
                     % floating_ip.address_readable)
        elif r.status_code != 204:
            msg = "Unexpected status from unicorn API: Status Code %s, " \
                  "Message: %s" % (r.status_code, r.json())
            LOG.error("remove_floating_ip: %s" % msg)
            raise ex.RemoveFloatingIpFailure(id=floating_ip.id)

    @classmethod
    def _build_fixed_ips(cls, port):
        fixed_ips = [{"ip_address": ip.address_readable,
                      "version": ip.version,
                      "subnet_id": ip.subnet.id,
                      "cidr": ip.subnet.cidr,
                      "address_type": ip.address_type}
                     for ip in port.ip_addresses
                     if (ip.get("address_type") == ip_types.FIXED)]
        return fixed_ips

    @classmethod
    def _build_endpoints(cls, port_fixed_ips):
        endpoints = []
        for port_id in port_fixed_ips:
            port = port_fixed_ips[port_id]["port"]
            fixed_ip = port_fixed_ips[port_id]["fixed_ip"]
            endpoint_port = {"uuid": port.id,
                             "name": port.name,
                             "network_uuid": port.network_id,
                             "mac_address": port.mac_address,
                             "device_id": port.device_id,
                             "device_owner": port.device_owner,
                             "fixed_ip": cls._build_fixed_ips(port)}
            endpoints.append({"port": endpoint_port,
                              "private_ip": fixed_ip.address_readable})
        return endpoints

    @classmethod
    def _build_request_body(cls, floating_ip, port_fixed_ips):
        content = {"public_ip": floating_ip["address_readable"],
                   "endpoints": cls._build_endpoints(port_fixed_ips)}
        return {"floating_ip": content}
