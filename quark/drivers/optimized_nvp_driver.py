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
Optimized NVP client for Quark
"""
import sqlalchemy as sa

from nvp_driver import NVPDriver
from quantum.openstack.common import log as logging
from quark.db import models
from sqlalchemy import orm

LOG = logging.getLogger("quantum.quark.nvplib")


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

        # slightly inefficient for the sake of brevity. Lets the
        # parent class do its thing then finds the switch that
        # the port was created on for creating the association. Switch should
        # be in the query cache so the subsequent lookup should be minimal,
        # but this could be an easy optimization later if we're looking.
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

    def _lswitch_select_first(self, context, network_id):
        query = context.session.query(LSwitch)
        query.filter(LSwitch.network_id == network_id)
        return query.first()

    def _lswitch_select_free(self, context, network_id):
        query = context.session.query(LSwitch)
        query = query.filter(LSwitch.port_count < self.max_ports_per_switch)
        query = query.filter(LSwitch.network_id == network_id)
        switch = query.order_by(LSwitch.port_count).first()
        return switch

    def _lswitch_status_query(self, context, network_id):
        """Child implementation of lswitch_status_query.

        Deliberately empty as we rely on _get_network_details to be more
        efficient than we can be here.
        """
        pass

    def _lswitch_select_open(self, context, network_id=None, **kwargs):
        if self.max_ports_per_switch == 0:
            switch = self._lswitch_select_first(context, network_id)
        else:
            switch = self._lswitch_select_free(context, network_id)
        if switch:
            return switch.nvp_id
        LOG.debug("Could not find optimized switch")

    def _get_network_details(self, context, network_id, switches):
        name, phys_net, phys_type, segment_id = None, None, None, None
        switch = self._lswitch_select_first(context, network_id)
        if switch:
            name = switch.display_name
            phys_net = switch.transport_zone
            phys_type = switch.transport_connector
            segment_id = switch.segment_id
            return dict(network_name=name, phys_net=phys_net,
                        phys_type=phys_type, segment_id=segment_id)

    def _lswitch_create(self, context, network_name=None, tags=None,
                        network_id=None, **kwargs):
        nvp_id = super(OptimizedNVPDriver, self).\
            _lswitch_create(context, network_name, tags,
                            network_id, **kwargs)
        return self._lswitch_create_optimized(context, network_name, nvp_id,
                                              network_id, **kwargs).nvp_id

    def _lswitch_create_optimized(self, context, network_name, nvp_id,
                                  network_id, phys_net=None, phys_type=None,
                                  segment_id=None):
        new_switch = LSwitch(nvp_id=nvp_id, network_id=network_id,
                             port_count=0, transport_zone=phys_net,
                             transport_connector=phys_type,
                             display_name=network_name,
                             segment_id=segment_id)
        context.session.add(new_switch)
        return new_switch

    def _lswitches_for_network(self, context, network_id):
        switches = context.session.query(LSwitch).\
            filter(LSwitch.network_id == network_id).\
            all()
        return switches


class LSwitchPort(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_lswitchport"
    port_id = sa.Column(sa.String(36), nullable=False)
    switch_id = sa.Column(sa.String(36),
                          sa.ForeignKey("quark_nvp_driver_lswitch.id"),
                          nullable=False)


class LSwitch(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_lswitch"
    nvp_id = sa.Column(sa.String(36), nullable=False)
    network_id = sa.Column(sa.String(36), nullable=False)
    display_name = sa.Column(sa.String(255))
    port_count = sa.Column(sa.Integer())
    ports = orm.relationship(LSwitchPort, backref='switch')
    transport_zone = sa.Column(sa.String(36))
    transport_connector = sa.Column(sa.String(20))
    segment_id = sa.Column(sa.Integer())


class QOS(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_qos"
    display_name = sa.Column(sa.String(255), nullable=False)
    max_bandwidth_rate = sa.Column(sa.Integer(), nullable=False)
    min_bandwidth_rate = sa.Column(sa.Integer(), nullable=False)
