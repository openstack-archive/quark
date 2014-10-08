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
from quark import protocols

CONF = cfg.CONF
LOG = logging.getLogger(__name__)
DEFAULT_SG_UUID = "00000000-0000-0000-0000-000000000000"


def _validate_security_group_rule(context, rule):
    # TODO(mdietz): As per RM8615, Remote groups are not currently supported
    if rule.get("remote_group_id"):
        raise exceptions.InvalidInput(
            error_message="Remote groups are not currently supported")

    if "direction" in rule and rule["direction"] != "ingress":
        raise exceptions.InvalidInput(
            error_message="Non-ingress rules are not currently supported")

    protocol = rule.pop('protocol')
    port_range_min = rule['port_range_min']
    port_range_max = rule['port_range_max']

    if protocol:
        protocol = protocols.translate_protocol(protocol, rule["ethertype"])
        protocols.validate_protocol_with_port_ranges(protocol,
                                                     port_range_min,
                                                     port_range_max)
        rule['protocol'] = protocol
    else:
        if port_range_min is not None or port_range_max is not None:
            raise sg_ext.SecurityGroupProtocolRequiredWithPorts()

    ethertype = protocols.translate_ethertype(rule["ethertype"])
    rule["ethertype"] = ethertype

    protocols.validate_remote_ip_prefix(ethertype,
                                        rule.get("remote_ip_prefix"))

    return rule


def create_security_group(context, security_group):
    LOG.info("create_security_group for tenant %s" %
             (context.tenant_id))
    group = security_group["security_group"]
    group_name = group.get('name', '')
    if group_name == "default":
        raise sg_ext.SecurityGroupDefaultAlreadyExists()
    group_id = uuidutils.generate_uuid()

    with context.session.begin():
        group["id"] = group_id
        group["name"] = group_name
        group["tenant_id"] = context.tenant_id
        dbgroup = db_api.security_group_create(context, **group)
    return v._make_security_group_dict(dbgroup)


def create_security_group_rule(context, security_group_rule):
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

        new_rule = db_api.security_group_rule_create(context, **rule)
    return v._make_security_group_rule_dict(new_rule)


def delete_security_group(context, id):
    LOG.info("delete_security_group %s for tenant %s" %
             (id, context.tenant_id))

    with context.session.begin():
        group = db_api.security_group_find(context, id=id, scope=db_api.ONE)

        # TODO(anyone): name and ports are lazy-loaded. Could be good op later
        if not group:
            raise sg_ext.SecurityGroupNotFound(group_id=id)
        if id == DEFAULT_SG_UUID or group.name == "default":
            raise sg_ext.SecurityGroupCannotRemoveDefault()
        if group.ports:
            raise sg_ext.SecurityGroupInUse(id=id)
        db_api.security_group_delete(context, group)


def delete_security_group_rule(context, id):
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


def update_security_group(context, id, security_group):
    if id == DEFAULT_SG_UUID:
        raise sg_ext.SecurityGroupCannotUpdateDefault()
    new_group = security_group["security_group"]
    with context.session.begin():
        group = db_api.security_group_find(context, id=id, scope=db_api.ONE)
        db_group = db_api.security_group_update(context, group, **new_group)
    return v._make_security_group_dict(db_group)
