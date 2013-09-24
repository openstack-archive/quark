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

from neutron.common import exceptions
from neutron.extensions import securitygroup as sg_ext
from neutron.openstack.common import log as logging
from neutron.openstack.common import uuidutils
from neutron import quota
from oslo.config import cfg

from quark.db import api as db_api
from quark import plugin_views as v


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
DEFAULT_SG_UUID = "00000000-0000-0000-0000-000000000000"


def _validate_security_group_rule(context, rule):
    PROTOCOLS = {"icmp": 1, "tcp": 6, "udp": 17}
    ALLOWED_WITH_RANGE = [6, 17]

    if rule.get("remote_ip_prefix") and rule.get("remote_group_id"):
        raise sg_ext.SecurityGroupRemoteGroupAndRemoteIpPrefix()

    protocol = rule.pop('protocol')
    port_range_min = rule['port_range_min']
    port_range_max = rule['port_range_max']

    if protocol:
        if isinstance(protocol, str):
            protocol = protocol.lower()
            protocol = PROTOCOLS.get(protocol)

        if not protocol:
            raise sg_ext.SecurityGroupRuleInvalidProtocol()

        if protocol in ALLOWED_WITH_RANGE:
            if (port_range_min is None) != (port_range_max is None):
                raise exceptions.InvalidInput(
                    error_message="For TCP/UDP rules, cannot wildcard "
                                  "only one end of port range.")
            if port_range_min is not None and port_range_max is not None:
                if port_range_min > port_range_max:
                    raise sg_ext.SecurityGroupInvalidPortRange()

        rule['protocol'] = protocol
    else:
        if port_range_min is not None or port_range_max is not None:
            raise sg_ext.SecurityGroupProtocolRequiredWithPorts()

    return rule


def create_security_group(context, security_group, net_driver):
    # TODO(dietz/perkins): passing in net_driver as a stopgap,
    # XXX DO NOT DEPLOY!! XXX see redmine #2487
    LOG.info("create_security_group for tenant %s" %
            (context.tenant_id))
    group = security_group["security_group"]
    group_name = group.get('name', '')
    if group_name == "default":
        raise sg_ext.SecurityGroupDefaultAlreadyExists()
    group_id = uuidutils.generate_uuid()

    with context.session.begin():
        net_driver.create_security_group(
            context,
            group_name,
            group_id=group_id,
            **group)

        group["id"] = group_id
        group["name"] = group_name
        group["tenant_id"] = context.tenant_id
        dbgroup = db_api.security_group_create(context, **group)
    return v._make_security_group_dict(dbgroup)


def _create_default_security_group(context, net_driver):
    default_group = {
        "name": "default", "description": "",
        "group_id": DEFAULT_SG_UUID,
        "port_egress_rules": [],
        "port_ingress_rules": [
            {"ethertype": "IPv4", "protocol": 1},
            {"ethertype": "IPv4", "protocol": 6},
            {"ethertype": "IPv4", "protocol": 17},
            {"ethertype": "IPv6", "protocol": 1},
            {"ethertype": "IPv6", "protocol": 6},
            {"ethertype": "IPv6", "protocol": 17},
        ]}

    net_driver.create_security_group(
        context,
        "default",
        **default_group)

    default_group["id"] = DEFAULT_SG_UUID
    default_group["tenant_id"] = context.tenant_id
    for rule in default_group.pop("port_ingress_rules"):
        db_api.security_group_rule_create(
            context, security_group_id=default_group["id"],
            tenant_id=context.tenant_id, direction="ingress",
            **rule)
    db_api.security_group_create(context, **default_group)


def create_security_group_rule(context, security_group_rule, net_driver):
    LOG.info("create_security_group for tenant %s" %
            (context.tenant_id))

    with context.session.begin():
        rule = _validate_security_group_rule(
            context, security_group_rule["security_group_rule"])
        rule["id"] = uuidutils.generate_uuid()

        group_id = rule["security_group_id"]
        group = db_api.security_group_find(context, id=group_id,
                                           scope=db_api.ONE)
        if not group:
            raise sg_ext.SecurityGroupNotFound(group_id=group_id)

        quota.QUOTAS.limit_check(
            context, context.tenant_id,
            security_rules_per_group=len(group.get("rules", [])) + 1)

        net_driver.create_security_group_rule(context, group_id, rule)

    return v._make_security_group_rule_dict(
        db_api.security_group_rule_create(context, **rule))


def delete_security_group(context, id, net_driver):
    LOG.info("delete_security_group %s for tenant %s" %
            (id, context.tenant_id))

    with context.session.begin():
        group = db_api.security_group_find(context, id=id, scope=db_api.ONE)

        #TODO(anyone): name and ports are lazy-loaded. Could be good op later
        if not group:
            raise sg_ext.SecurityGroupNotFound(group_id=id)
        if id == DEFAULT_SG_UUID or group.name == "default":
            raise sg_ext.SecurityGroupCannotRemoveDefault()
        if group.ports:
            raise sg_ext.SecurityGroupInUse(id=id)
        net_driver.delete_security_group(context, id)
        db_api.security_group_delete(context, group)


def delete_security_group_rule(context, id, net_driver):
    LOG.info("delete_security_group %s for tenant %s" %
            (id, context.tenant_id))
    with context.session.begin():
        rule = db_api.security_group_rule_find(context, id=id,
                                               scope=db_api.ONE)
        if not rule:
            raise sg_ext.SecurityGroupRuleNotFound(group_id=id)

        group = db_api.security_group_find(context, id=rule["group_id"],
                                           scope=db_api.ONE)
        if not group:
            raise sg_ext.SecurityGroupNotFound(id=id)

        net_driver.delete_security_group_rule(
            context, group.id, v._make_security_group_rule_dict(rule))

        rule["id"] = id
        db_api.security_group_rule_delete(context, rule)


def get_security_group(context, id, fields=None):
    LOG.info("get_security_group %s for tenant %s" %
            (id, context.tenant_id))
    group = db_api.security_group_find(context, id=id, scope=db_api.ONE)
    if not group:
        raise sg_ext.SecurityGroupNotFound(group_id=id)
    return v._make_security_group_dict(group, fields)


def get_security_group_rule(context, id, fields=None):
    LOG.info("get_security_group_rule %s for tenant %s" %
            (id, context.tenant_id))
    rule = db_api.security_group_rule_find(context, id=id,
                                           scope=db_api.ONE)
    if not rule:
        raise sg_ext.SecurityGroupRuleNotFound(rule_id=id)
    return v._make_security_group_rule_dict(rule, fields)


def get_security_groups(context, filters=None, fields=None,
                        sorts=None, limit=None, marker=None,
                        page_reverse=False):
    LOG.info("get_security_groups for tenant %s" %
            (context.tenant_id))
    groups = db_api.security_group_find(context, **filters)
    return [v._make_security_group_dict(group) for group in groups]


def get_security_group_rules(context, filters=None, fields=None,
                             sorts=None, limit=None, marker=None,
                             page_reverse=False):
    LOG.info("get_security_group_rules for tenant %s" %
            (context.tenant_id))
    rules = db_api.security_group_rule_find(context, **filters)
    return [v._make_security_group_rule_dict(rule) for rule in rules]


def update_security_group(context, id, security_group, net_driver):
    if id == DEFAULT_SG_UUID:
        raise sg_ext.SecurityGroupCannotUpdateDefault()
    new_group = security_group["security_group"]
    with context.session.begin():
        group = db_api.security_group_find(context, id=id, scope=db_api.ONE)
        net_driver.update_security_group(context, id, **new_group)

        db_group = db_api.security_group_update(context, group, **new_group)
    return v._make_security_group_dict(db_group)
