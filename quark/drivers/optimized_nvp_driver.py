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
Optimized NVP client for Quark
"""

import aiclib
from oslo_log import log as logging

from quark.db import models
from quark.drivers.nvp_driver import NVPDriver

import sqlalchemy as sa
from sqlalchemy import orm

LOG = logging.getLogger(__name__)


class OptimizedNVPDriver(NVPDriver):
    def __init__(self):
        super(OptimizedNVPDriver, self).__init__()

    @classmethod
    def get_name(klass):
        return "NVP"

    def delete_network(self, context, network_id):
        lswitches = self._lswitches_for_network(context, network_id)
        for switch in lswitches:
            try:
                self._lswitch_delete(context, switch.nvp_id)
                self._remove_default_tz_bindings(
                    context, network_id)
            except aiclib.core.AICException as ae:
                LOG.info("LSwitch/Network %s found in database."
                         " Adding to orphaned database table."
                         % network_id)
                if ae.code != 404:
                    LOG.info("LSwitch/Network %s was found in NVP."
                             " Adding to orpaned table for later cleanup."
                             " Code: %s, Message: %s"
                             % (network_id, ae.code, ae.message))
                    orphaned_lswitch = OrphanedLSwitch(
                        nvp_id=switch.nvp_id,
                        network_id=switch.network_id,
                        display_name=switch.display_name
                    )
                    context.session.add(orphaned_lswitch)
                LOG.info("Deleting LSwitch/Network %s from original"
                         " table." % network_id)
                context.session.delete(switch)
            except Exception as e:
                message = e.args[0] if e.args else ''
                LOG.info("Failed to delete LSwitch/Network %s from "
                         " NVP (optimized). Message: %s"
                         % (network_id, message))

    def create_port(self, context, network_id, port_id,
                    status=True, security_groups=None,
                    device_id="", **kwargs):
        security_groups = security_groups or []
        nvp_port = super(OptimizedNVPDriver, self).create_port(
            context, network_id, port_id, status=status,
            security_groups=security_groups, device_id=device_id)
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

    def update_port(self, context, port_id, status=True,
                    security_groups=None, **kwargs):
        security_groups = security_groups or []
        mac_address = kwargs.get('mac_address')
        device_id = kwargs.get('device_id')
        nvp_port = super(OptimizedNVPDriver, self).update_port(
            context, port_id, mac_address=mac_address, device_id=device_id,
            status=status, security_groups=security_groups)
        port = self._lport_select_by_id(context, port_id)
        port.update(nvp_port)

    def delete_port(self, context, port_id, **kwargs):
        port = self._lport_select_by_id(context, port_id)
        if not port:
            LOG.warning("Lost local reference to NVP lport %s" % port_id)
            return  # we return here because there isn't anything else to do

        switch = port.switch
        try:
            self._lport_delete(context, port_id, switch)
        except aiclib.core.AICException as ae:
            LOG.info("LSwitchPort/Port %s found in database."
                     " Adding to orphaned database table."
                     % port_id)
            if ae.code != 404:
                LOG.info("LSwitchPort/Port %s was found in NVP."
                         " Adding to orpaned table for later cleanup."
                         " Code: %s, Message: %s"
                         % (port_id, ae.code, ae.args[0]))
                orphaned_lswitch_port = OrphanedLSwitchPort(
                    port_id=port_id,
                )
                context.session.add(orphaned_lswitch_port)
        except Exception as e:
            LOG.info("Failed to delete LSwitchPort/Port %s from "
                     " NVP (optimized). Message: %s"
                     % (port_id, e.args[0]))
        LOG.info("Deleting LSwitchPort/Port %s from original"
                 " table." % port_id)
        context.session.delete(port)
        switch.port_count = switch.port_count - 1
        if switch.port_count == 0:
            switches = self._lswitches_for_network(context, switch.network_id)
            if len(switches) > 1:  # do not delete last lswitch on network
                self._lswitch_delete(context, switch.nvp_id)

    def _lport_delete(self, context, port_id, switch=None):
        if switch is None:
            port = self._lport_select_by_id(context, port_id)
            switch = port.switch
        super(OptimizedNVPDriver, self).delete_port(
            context, port_id, lswitch_uuid=switch.nvp_id)

    def create_security_group(self, context, group_name, **group):
        nvp_group = super(OptimizedNVPDriver, self).create_security_group(
            context, group_name, **group)
        group_id = group.get('group_id')
        profile = SecurityProfile(id=group_id, nvp_id=nvp_group['uuid'])
        context.session.add(profile)

    def delete_security_group(self, context, group_id, **kwargs):
        super(OptimizedNVPDriver, self).delete_security_group(
            context, group_id)
        group = self._query_security_group(context, group_id)
        context.session.delete(group)

    def _lport_select_by_id(self, context, port_id):
        query = context.session.query(LSwitchPort)
        query = query.filter(LSwitchPort.port_id == port_id)
        return query.first()

    def _lswitch_delete(self, context, lswitch_uuid):
        switch = self._lswitch_select_by_nvp_id(context, lswitch_uuid)
        super(OptimizedNVPDriver, self)._lswitch_delete(
            context, lswitch_uuid)
        context.session.delete(switch)

    def _lswitch_select_by_nvp_id(self, context, nvp_id):
        switch = context.session.query(LSwitch).filter(
            LSwitch.nvp_id == nvp_id).first()
        return switch

    def _lswitch_select_first(self, context, network_id):
        query = context.session.query(LSwitch)
        query = query.filter(LSwitch.network_id == network_id)
        return query.first()

    def _lswitch_select_free(self, context, network_id):
        query = context.session.query(LSwitch)
        query = query.filter(LSwitch.port_count <
                             self.limits['max_ports_per_switch'])
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
        if self.limits['max_ports_per_switch'] == 0:
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
        nvp_id = super(OptimizedNVPDriver, self)._lswitch_create(
            context, network_name, tags, network_id, **kwargs)
        return self._lswitch_create_optimized(context, network_name, nvp_id,
                                              network_id, **kwargs).nvp_id

    def _lswitch_create_optimized(self, context, network_name, nvp_id,
                                  network_id, phys_net=None, phys_type=None,
                                  segment_id=None):
        new_switch = LSwitch(nvp_id=nvp_id, network_id=network_id,
                             port_count=0, transport_zone=phys_net,
                             transport_connector=phys_type,
                             display_name=network_name[:40],
                             segment_id=segment_id)
        context.session.add(new_switch)
        return new_switch

    def get_lswitch_ids_for_network(self, context, network_id):
        """Public interface for fetching lswitch ids for a given network.

        NOTE(morgabra) This is here because calling private methods
        from outside the class feels wrong, and we need to be able to
        fetch lswitch ids for use in other drivers.
        """
        lswitches = self._lswitches_for_network(context, network_id)
        return [s['nvp_id'] for s in lswitches]

    def _lswitches_for_network(self, context, network_id):
        switches = context.session.query(LSwitch).filter(
            LSwitch.network_id == network_id).all()
        return switches

    def _lswitch_from_port(self, context, port_id):
        port = self._lport_select_by_id(context, port_id)
        return port.switch.nvp_id

    def _query_security_group(self, context, group_id):
        return context.session.query(SecurityProfile).filter(
            SecurityProfile.id == group_id).first()

    def _make_security_rule_dict(self, rule):
        res = {"port_range_min": rule.get("port_range_min"),
               "port_range_max": rule.get("port_range_max"),
               "protocol": rule.get("protocol"),
               "ip_prefix": rule.get("remote_ip_prefix"),
               "group_id": rule.get("remote_group_id"),
               "ethertype": rule.get("ethertype")}
        for key, value in res.items():
            if value is None:
                res.pop(key)
        return res

    def _get_security_group(self, context, group_id):
        group = context.session.query(models.SecurityGroup).filter(
            models.SecurityGroup.id == group_id).first()
        rulelist = {'ingress': [], 'egress': []}
        for rule in group.rules:
            rulelist[rule.direction].append(
                self._make_security_rule_dict(rule))
        return {'uuid': self._query_security_group(context, group_id).nvp_id,
                'logical_port_ingress_rules': rulelist['ingress'],
                'logical_port_egress_rules': rulelist['egress']}

    def _check_rule_count_per_port(self, context, group_id):
        ports = context.session.query(models.SecurityGroup).filter(
            models.SecurityGroup.id == group_id).first().get('ports', [])
        groups = (set(group.id for group in port.get('security_groups', []))
                  for port in ports)
        return max(self._check_rule_count_for_groups(
            context, (self._get_security_group(context, id) for id in g))
            for g in groups)


class LSwitchPort(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_lswitchport"
    port_id = sa.Column(sa.String(36), nullable=False, index=True)
    switch_id = sa.Column(sa.String(36),
                          sa.ForeignKey("quark_nvp_driver_lswitch.id"),
                          nullable=False)


class LSwitch(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_lswitch"
    nvp_id = sa.Column(sa.String(36), nullable=False, index=True)
    network_id = sa.Column(sa.String(36), nullable=False, index=True)
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


class SecurityProfile(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_driver_security_profile"
    nvp_id = sa.Column(sa.String(36), nullable=False, index=True)


class OrphanedLSwitch(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_orphaned_lswitches"
    nvp_id = sa.Column(sa.String(36), nullable=False, index=True)
    network_id = sa.Column(sa.String(36), nullable=False, index=True)
    display_name = sa.Column(sa.String(255), index=True)


class OrphanedLSwitchPort(models.BASEV2, models.HasId):
    __tablename__ = "quark_nvp_orphaned_lswitch_ports"
    port_id = sa.Column(sa.String(36), nullable=False, index=True)
