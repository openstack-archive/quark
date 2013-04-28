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
NVP client driver for Quark
"""

from oslo.config import cfg

import sqlalchemy as sa
from sqlalchemy import orm

import aiclib
from quantum.openstack.common import log as logging

from quark.db import models
from quark.drivers import base


LOG = logging.getLogger("quantum.quark.nvplib")

CONF = cfg.CONF

nvp_opts = [
    cfg.IntOpt('max_ports_per_switch',
               default=0,
               help=_('Maximum amount of NVP ports on an NVP lswitch')),
    cfg.StrOpt('default_tz',
               help=_('The default transport zone UUID')),
    cfg.MultiStrOpt('controller_connection',
                    default=[],
                    help=_('NVP Controller connection string')),
]

CONF.register_opts(nvp_opts, "NVP")


class NVPDriver(base.BaseDriver):
    def __init__(self):
        self.nvp_connections = []
        self.conn_index = 0
        self.max_ports_per_switch = 0

    def load_config(self, path):
        default_tz = CONF.NVP.default_tz
        connections = CONF.NVP.controller_connection
        self.max_ports_per_switch = CONF.NVP.max_ports_per_switch
        for conn in connections:
            (ip, port, user, pw, req_timeout,
             http_timeout, retries, redirects) = conn.split(":")

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
        if "connection" not in conn:
            scheme = conn["port"] == "443" and "https" or "http"
            uri = "%s://%s:%s" % (scheme, conn["ip_address"], conn["port"])
            user = conn['username']
            passwd = conn['password']
            conn["connection"] = aiclib.nvp.Connection(uri,
                                                       username=user,
                                                       password=passwd)
        return conn["connection"]

    def create_network(self, context, network_name, tags=None,
                       network_id=None, **kwargs):
        return self._lswitch_create(context, network_name, tags,
                                    network_id, **kwargs)

    def delete_network(self, context, network_id):
        lswitches = self._lswitches_for_network(context, network_id).results()
        connection = self.get_connection()
        for switch in lswitches["results"]:
            LOG.debug("Deleting lswitch %s" % switch["uuid"])
            connection.lswitch(switch["uuid"]).delete()

    def create_port(self, context, network_id, port_id, status=True):
        tenant_id = context.tenant_id
        lswitch = self._create_or_choose_lswitch(context, network_id)
        connection = self.get_connection()
        port = connection.lswitch_port(lswitch)
        port.admin_status_enabled(status)
        tags = [dict(tag=network_id, scope="quantum_net_id"),
                dict(tag=port_id, scope="quantum_port_id"),
                dict(tag=tenant_id, scope="os_tid")]
        LOG.debug("Creating port on switch %s" % lswitch)
        port.tags(tags)
        res = port.create()
        res["lswitch"] = lswitch
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

    def _create_or_choose_lswitch(self, context, network_id):
        tenant_id = context.tenant_id
        LOG.debug("Choosing an appropriate lswitch for %s" % tenant_id)
        LOG.debug("Max ports per switch %d" % self.max_ports_per_switch)
        switch = self._lswitch_select_open(context, network_id)
        if switch:
            LOG.debug("Found open switch %s" % switch)
            return switch

        return self._lswitch_create(context, network_id,
                                    network_id=network_id)

    def _lswitch_select_open(self, context, network_id):
        query = self._lswitches_for_network(context, network_id)
        query.relations("LogicalSwitchStatus")
        results = query.results()
        LOG.debug("Query results: %s" % results)
        for res in results["results"]:
            count = res["_relations"]["LogicalSwitchStatus"]["lport_count"]
            if self.max_ports_per_switch == 0 or \
                    count < self.max_ports_per_switch:
                return res["uuid"]
        return None

    def _lswitch_delete(self, context, lswitch_uuid):
        connection = self.get_connection()
        LOG.debug("Deleting lswitch %s" % lswitch_uuid)
        connection.lswitch(lswitch_uuid).delete()

    def _lswitch_create(self, context, network_name, tags=None,
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
        return res["uuid"]

    def _lswitches_for_network(self, context, network_id):
        connection = self.get_connection()
        query = connection.lswitch().query()
        tags = [dict(tag=network_id, scope="quantum_net_id"),
                dict(tag=context.tenant_id, scope="os_tid")]
        query.tags(tags)
        return query


class OptimizedNVPDriver(NVPDriver):
    def delete_network(self, context, network_id):
        lswitches = self._lswitches_for_network(context, network_id)
        for switch in lswitches:
            self._lswitch_delete(context, switch.nvp_id)

    def create_port(self, context, network_id, port_id, status=True):
        nvp_port = super(OptimizedNVPDriver, self).\
            create_port(context, network_id,
                        port_id, status)
        switch_nvp_id = nvp_port["lswitch"]
        switch = self._lswitch_select_by_nvp_id(context, switch_nvp_id)
        new_port = LSwitchPort(port_id=nvp_port["uuid"],
                               switch_id=switch.id)
        context.session.add(new_port)
        switch.port_count = switch.port_count + 1
        return nvp_port

    def delete_port(self, context, port_id, lswitch_uuid=None):
        port = self._lport_select_by_id(context, port_id)
        switch = port.switch
        super(OptimizedNVPDriver, self).\
            delete_port(context, port_id, lswitch_uuid=switch.nvp_id)
        context.session.delete(port)
        switch.port_count = switch.port_count - 1
        if switch.port_count == 0:
            self._lswitch_delete(context, switch.nvp_id)

    def _lport_select_by_id(self, context, port_id):
        port = context.session.query(LSwitchPort).\
            filter(LSwitchPort.port_id == port_id).\
            first()
        return port

    def _lswitch_delete(self, context, lswitch_uuid):
        switch = self._lswitch_select_by_nvp_id(context, lswitch_uuid)
        super(OptimizedNVPDriver, self).\
            _lswitch_delete(context, lswitch_uuid)
        context.session.delete(switch)

    def _lswitch_select_by_nvp_id(self, context, nvp_id):
        switch = context.session.query(LSwitch).\
            filter(LSwitch.nvp_id == nvp_id).\
            first()
        return switch

    def _lswitch_select_first(self, context):
        return context.session.query(LSwitch).first()

    def _lswitch_select_free(self, context):
        switch = context.session.query(LSwitch).\
            filter(LSwitch.port_count < self.max_ports_per_switch).\
            order_by(LSwitch.port_count).\
            first()
        return switch

    def _lswitch_select_open(self, context, network_id):
        if self.max_ports_per_switch == 0:
            switch = self._lswitch_select_first(context)
        else:
            switch = self._lswitch_select_free(context)
        if not switch:
            LOG.debug("Could not find optimized switch")
            return None
        return switch.nvp_id

    def _lswitch_create(self, context, network_name, tags=None,
                        network_id=None, **kwargs):
        nvp_id = super(OptimizedNVPDriver, self).\
            _lswitch_create(context, network_name, tags,
                            network_id, **kwargs)
        return self._lswitch_create_optimized(context, nvp_id,
                                              network_id).nvp_id

    def _lswitch_create_optimized(self, context, nvp_id, network_id):
        new_switch = LSwitch(nvp_id=nvp_id, network_id=network_id,
                             port_count=0)
        context.session.add(new_switch)
        return new_switch

    def _lswitches_for_network(self, context, network_id):
        switches = context.session.query(LSwitch).\
            filter(LSwitch.network_id == network_id).\
            all()
        return switches


class QOS(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_qos"
    display_name = sa.Column(sa.String(255), nullable=False)
    max_bandwidth_rate = sa.Column(sa.Integer(), nullable=False)
    min_baddwidth_rate = sa.Column(sa.Integer(), nullable=False)


class LSwitchPort(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_lswitchport"
    port_id = sa.Column(sa.String(255), nullable=False)
    switch_id = sa.Column(sa.String(255),
                          sa.ForeignKey("quark_nvp_driver_lswitch.id"),
                          nullable=False)


class LSwitch(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_lswitch"
    nvp_id = sa.Column(sa.String(255), nullable=False)
    network_id = sa.Column(sa.String(255), nullable=False)
    port_count = sa.Column(sa.Integer())
    ports = orm.relationship(LSwitchPort, backref='switch')
