# Copyright 2013 Openstack LLC.
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
NVP client driver for Quark
"""

import ConfigParser

import aiclib
from quantum.openstack.common import log as logging

#from quark.db import models
from quark.drivers import base
from quark import exceptions as quark_exceptions


LOG = logging.getLogger("quantum.quark.nvplib")


class NVPDriver(base.BaseDriver):
    def __init__(self):
        self.nvp_connections = []
        self.conn_index = 0

    def load_config(self, path):
        config = ConfigParser.ConfigParser()
        config.read(path)
        default_tz = config.get("NVP", "DEFAULT_TZ_UUID")
        connections = config.get("NVP", "NVP_CONTROLLER_CONNECTIONS")
        for conn in connections.split():
            (ip, port, user, pw, req_timeout,
             http_timeout, retries, redirects) =\
                config.get("NVP", conn).split(":")
            self.nvp_connections.append(dict(ip_address=ip,
                                        port=port,
                                        username=user,
                                        password=pw,
                                        req_timeout=req_timeout,
                                        http_timeout=http_timeout,
                                        retries=retries,
                                        redirects=redirects,
                                        default_tz=default_tz))

    def get_connection(self):
        conn = self.nvp_connections[self.conn_index]
        if not "connection" in conn:
            scheme = conn["port"] == "443" and "https" or "http"
            uri = "%s://%s:%s" % (scheme, conn["ip_address"], conn["port"])
            conn["connection"] = aiclib.nvp.Connection(uri)
        return conn["connection"]

    def create_network(self, tenant_id, network_name, tags=None,
                       network_id=None, **kwargs):
        return self._create_lswitch(tenant_id, network_name, tags,
                                    network_id, **kwargs)

    def delete_network(self, context, network_id):
        connection = self.get_connection()
        query = connection.lswitch().query()
        tags = [dict(tag=network_id, scope="quantum_net_id")]
        query.tags(tags)
        lswitches = query.results()
        for switch in lswitches["results"]:
            LOG.debug("Deleting lswitch %s" % switch["uuid"])
            connection.lswitch(switch["uuid"]).delete()

    def _get_open_lswitch(self, context, network_id, max_per_switch):
        query = self._lswitch_query(context, network_id)
        query.relations("LogicalSwitchStatus")
        results = query.results()
        for res in results["results"]:
            count = res["_relations"]["LogicalSwitchStatus"]["lport_count"]
            if count < max_per_switch:
                return res["uuid"]
        return None

    def _get_lswitch_for_network(self, context, network_id):
        LOG.debug("Finding lswitch for network %s" % network_id)
        results = self._lswitch_query(context, network_id).results()
        if results["result_count"] > 1:
            raise quark_exceptions.AmbiguousLswitchCount(net_id=network_id)
        return results["results"][0]

    def _lswitch_query(self, context, network_id):
        connection = self.get_connection()
        query = connection.lswitch().query()
        tags = [dict(tag=network_id, scope="quantum_net_id"),
                dict(tag=context.tenant_id, scope="os_tid")]
        query.tags(tags)
        return query

    def _create_or_choose_lswitch(self, context, network_id, max_per_switch=0):
        tenant_id = context.tenant_id
        LOG.debug("Choosing an appropriate lswitch for %s" % tenant_id)
        if max_per_switch > 0:
            LOG.debug("Max ports per switch %d" % max_per_switch)
            switch = self._get_open_lswitch(context, network_id,
                                            max_per_switch)
            if switch:
                LOG.debug("Found open switch %s" % switch)
                return switch

            # if we get here, time to make a new switch
            return self._create_lswitch(tenant_id, network_id,
                                        network_id=network_id)["uuid"]

        return self._get_lswitch_for_network(context, network_id)

    def create_port(self, context, network_id, port_id, status=True):
        tenant_id = context.tenant_id
        lswitch = self._create_or_choose_lswitch(context, network_id)
        connection = self.get_connection()
        port = connection.lswitch_port(lswitch)
        port.admin_status_enabled(status)
        tags = [dict(tag=network_id, scope="quantum_net_id"),
                dict(tag=port_id, scope="quantum_port_id"),
                dict(tag=tenant_id, scope="os_tid")]
        LOG.debug("Creating port on switch %s" % lswitch["uuid"])
        port.tags(tags)
        res = port.create()
        return res

    def delete_port(self, context, port_id, lswitch_uuid=None):
        connection = self.get_connection()
        if not lswitch_uuid:
            query = connection.lswitch_port("*").query()
            query.relations("LogicalSwitchConfig")
            query.uuid(port_id)
            port = query.results()
            if port["result_count"] > 1:
                raise Exception("More than one lswitch for port %s" % port_id)
            for r in port["results"]:
                lswitch_uuid = r["_relations"]["LogicalSwitchConfig"]["uuid"]
        LOG.debug("Deleting port %s from lswitch %s" % (port_id, lswitch_uuid))
        connection.lswitch_port(lswitch_uuid, port_id).delete()

    def _create_lswitch(self, context, network_name, tags=None,
                        network_id=None, **kwargs):
        LOG.debug("Creating new lswitch for %s network %s" %
                 (context.tenant_id, network_name))
        tenant_id = context.tenant_id
        connection = self.get_connection()
        switch = connection.lswitch()
        switch.display_name(network_name)
        tags = tags or []
        tags.append({"tag": tenant_id, "scope": "os_tid"})
        if network_id:
            tags.append({"tag": network_id, "scope": "quantum_net_id"})
        switch.tags(tags)
        LOG.debug("Creating lswitch for network %s" % network_id)
        res = switch.create()
        return res


class OptimizedNVPDriver(NVPDriver):
    def _get_open_lswitch(self, context, network_id, max_per_switch):
        #TODO: use the lswitch table here
        return super(OptimizedNVPDriver, self)._get_open_lswitch(
            context, network_id, max_per_switch)

    def _get_lswitch_for_network(self, context, network_id):
        #TODO: use the lswitch table here
        return super(OptimizedNVPDriver, self)._get_lswitch_for_network(
            context, network_id)
