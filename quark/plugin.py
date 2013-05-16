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
v2 Quantum Plug-in API Quark Implementation
"""
import inspect

import netaddr

from oslo.config import cfg

from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy import event
from zope import sqlalchemy as zsa

from quantum.api.v2 import attributes
from quantum.common import config as quantum_cfg
from quantum.common import exceptions
from quantum.db import api as quantum_db_api
from quantum.extensions import securitygroup as sg_ext
from quantum import quantum_plugin_base_v2

from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils

from quark.api import extensions
from quark.db import api as db_api
from quark.db import models
from quark import exceptions as quark_exceptions
from quark import network_strategy

LOG = logging.getLogger("quantum.quark")
CONF = cfg.CONF
DEFAULT_ROUTE = netaddr.IPNetwork("0.0.0.0/0")


quark_opts = [
    cfg.StrOpt('net_driver',
               default='quark.drivers.base.BaseDriver',
               help=_('The client to use to talk to the backend')),
    cfg.StrOpt('ipam_driver', default='quark.ipam.QuarkIpam',
               help=_('IPAM Implementation to use')),
    cfg.BoolOpt('ipam_reuse_after', default=7200,
                help=_("Time in seconds til IP and MAC reuse"
                       "after deallocation.")),
    cfg.StrOpt("strategy_driver",
               default='quark.network_strategy.JSONStrategy',
               help=_("Tree of network assignment strategy")),
    cfg.StrOpt('net_driver_cfg', default='/etc/quantum/quark.ini',
               help=_("Path to the config for the net driver"))
]


STRATEGY = network_strategy.STRATEGY

CONF.register_opts(quark_opts, "QUARK")


# NOTE(jkoelker) init event listener that will ensure id is filled in
#                on object creation (prior to commit).
def perhaps_generate_id(target, args, kwargs):
    if hasattr(target, 'id') and target.id is None:
        target.id = uuidutils.generate_uuid()


def append_quark_extensions(conf):
    """Adds the Quark API Extensions to the extension path.

    Pulled out for test coveage.
    """
    if 'api_extensions_path' in conf:
        conf.set_override('api_extensions_path', ":".join(extensions.__path__))

append_quark_extensions(CONF)


def _pop_param(attrs, param, default=None):
    val = attrs.pop(param, default)
    if val is attributes.ATTR_NOT_SPECIFIED:
        return default
    return val


class Plugin(quantum_plugin_base_v2.QuantumPluginBaseV2,
             sg_ext.SecurityGroupPluginBase):
    # NOTE(mdietz): I hate this
    supported_extension_aliases = ["mac_address_ranges", "routes",
                                   "ip_addresses", "ports_quark",
                                   "security-group",
                                   "subnets_quark"]

    def _initDBMaker(self):
        # This needs to be called after _ENGINE is configured
        session_maker = sessionmaker(bind=quantum_db_api._ENGINE,
                                     extension=zsa.ZopeTransactionExtension())
        quantum_db_api._MAKER = scoped_session(session_maker)

    def __init__(self):
        # NOTE(jkoelker) Register the event on all models that have ids
        for _name, klass in inspect.getmembers(models, inspect.isclass):
            if klass is models.HasId:
                continue

            if models.HasId in klass.mro():
                event.listen(klass, "init", perhaps_generate_id)

        quantum_db_api.configure_db()
        self._initDBMaker()
        self.net_driver = (importutils.import_class(CONF.QUARK.net_driver))()
        self.net_driver.load_config(CONF.QUARK.net_driver_cfg)
        self.ipam_driver = (importutils.import_class(CONF.QUARK.ipam_driver))()
        self.ipam_reuse_after = CONF.QUARK.ipam_reuse_after
        models.BASEV2.metadata.create_all(quantum_db_api._ENGINE)

    def _make_network_dict(self, network, fields=None):
        shared_net = STRATEGY.is_parent_network(network["id"])
        res = {'id': network["id"],
               'name': network.get('name'),
               'tenant_id': network.get('tenant_id'),
               'admin_state_up': None,
               'status': network.get('status'),
               'shared': shared_net,
               #TODO(mdietz): this is the expected return. Then the client
               #              foolishly turns around and asks for the entire
               #              subnet list anyway! Plz2fix
               'subnets': [s["id"] for s in network.get("subnets", [])]}
        return res

    def _make_subnet_dict(self, subnet, fields=None):
        dns_nameservers = [str(netaddr.IPAddress(dns["ip"]))
                           for dns in subnet.get("dns_nameservers")]
        # TODO(mdietz): this is a hack to get nova to boot. We want to get the
        #               "default" route out of the database and use that
        net_id = STRATEGY.get_parent_network(subnet["network_id"])
        res = {"id": subnet.get('id'),
               "name": subnet.get('name'),
               "tenant_id": subnet.get('tenant_id'),
               "network_id": net_id,
               "ip_version": subnet.get('ip_version'),
               "allocation_pools": [],
               "dns_nameservers": dns_nameservers or [],
               "cidr": subnet.get('cidr'),
               "enable_dhcp": None}

        def _host_route(route):
            return {"destination": route["cidr"],
                    "nexthop": route["gateway"]}

        res["host_routes"] = [_host_route(r) for r in subnet["routes"]]

        #TODO(mdietz): really inefficient, should go away
        for route in subnet["routes"]:
            if netaddr.IPNetwork(route["cidr"]) == DEFAULT_ROUTE:
                res["gateway_ip"] = route["gateway"]
                break
        return res

    def _make_security_group_dict(self, security_group, fields=None):
        res = {"id": security_group.get("id"),
               "description": security_group.get("description"),
               "name": security_group.get("name"),
               "tenant_id": security_group.get("tenant_id")}
        res["security_group_rules"] =\
            [self._make_security_group_rule_dict(r)
                for r in security_group['rules']]
        return res

    def _make_security_group_rule_dict(self, security_rule, fields=None):
        res = {"id": security_rule.get("id"),
               "direction": security_rule.get("direction"),
               "tenant_id": security_rule.get("tenant_id"),
               "port_range_max": security_rule.get("port_range_max"),
               "port_range_mid": security_rule.get("port_range_mid"),
               "protocol": security_rule.get("protocol"),
               "remote_ip_prefix": security_rule.get("remote_ip_prefix"),
               "security_group_id": security_rule.get("security_group_id"),
               "remote_group_id": security_rule.get("remote_group_id")}
        return res

    def _port_dict(self, port, fields=None):
        res = {"id": port.get("id"),
               "name": port.get("name"),
               "network_id": STRATEGY.get_parent_network(port["network_id"]),
               "tenant_id": port.get("tenant_id"),
               "mac_address": port.get("mac_address"),
               "admin_state_up": port.get("admin_state_up"),
               "status": port.get("status"),
               "device_id": port.get("device_id"),
               "device_owner": port.get("device_owner")}
        if isinstance(res["mac_address"], (int, long)):
            res["mac_address"] = str(netaddr.EUI(res["mac_address"],
                                     dialect=netaddr.mac_unix))
        return res

    def _make_port_address_dict(self, ip):
        return {'subnet_id': ip.get("subnet_id"),
                'ip_address': ip.formatted()}

    def _make_port_dict(self, port, fields=None):
        res = self._port_dict(port)
        res["fixed_ips"] = [self._make_port_address_dict(ip)
                            for ip in port.ip_addresses]
        return res

    def _make_ports_list(self, query, fields=None):
        ports = []
        for port in query:
            port_dict = self._port_dict(port, fields)
            port_dict["fixed_ips"] = [self._make_port_address_dict(addr)
                                      for addr in port.ip_addresses]
            ports.append(port_dict)
        return ports

    def _make_subnets_list(self, query, fields=None):
        subnets = []
        for subnet in query:
            subnet_dict = self._make_subnet_dict(subnet, fields)
            subnets.append(subnet_dict)
        return subnets

    def _make_mac_range_dict(self, mac_range):
        return {"id": mac_range["id"],
                "cidr": mac_range["cidr"]}

    def _make_route_dict(self, route):
        return {"id": route["id"],
                "cidr": route["cidr"],
                "gateway": route["gateway"],
                "subnet_id": route["subnet_id"]}

    def _make_ip_dict(self, address):
        net_id = STRATEGY.get_parent_network(address["network_id"])
        return {"id": address["id"],
                "network_id": net_id,
                "address": address.formatted(),
                "port_ids": [port["id"] for port in address["ports"]],
                "device_ids": [port["device_id"] for port in address["ports"]],
                "subnet_id": address["subnet_id"],
                "tenant_id": address["tenant_id"],
                "shared": len(address["ports"]) > 1}

    def _validate_subnet_cidr(self, context, network, new_subnet_cidr):
        """Validate the CIDR for a subnet.

        Verifies the specified CIDR does not overlap with the ones defined
        for the other subnets specified for this network, or with any other
        CIDR if overlapping IPs are disabled.

        """
        new_subnet_ipset = netaddr.IPSet([new_subnet_cidr])
        if quantum_cfg.cfg.CONF.allow_overlapping_ips:
            subnet_list = network.subnets
        else:
            subnet_list = db_api.subnet_find(context.elevated())
        for subnet in subnet_list:
            if (netaddr.IPSet([subnet.cidr]) & new_subnet_ipset):
                # don't give out details of the overlapping subnet
                err_msg = (_("Requested subnet with cidr: %(cidr)s for "
                             "network: %(network_id)s overlaps with another "
                             "subnet") %
                           {'cidr': new_subnet_cidr,
                            'network_id': network.id})
                LOG.error(_("Validation for CIDR: %(new_cidr)s failed - "
                            "overlaps with subnet %(subnet_id)s "
                            "(CIDR: %(cidr)s)"),
                          {'new_cidr': new_subnet_cidr,
                           'subnet_id': subnet.id,
                           'cidr': subnet.cidr})
                raise exceptions.InvalidInput(error_message=err_msg)

    def create_subnet(self, context, subnet):
        """Create a subnet.

        Create a subnet which represents a range of IP addresses
        that can be allocated to devices

        : param context: quantum api request context
        : param subnet: dictionary describing the subnet, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_subnet for tenant %s" % context.tenant_id)
        net_id = subnet["subnet"]["network_id"]

        net = db_api.network_find(context, id=net_id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=net_id)

        sub_attrs = subnet["subnet"]

        self._validate_subnet_cidr(context, net, sub_attrs["cidr"])

        cidr = netaddr.IPNetwork(sub_attrs["cidr"])
        gateway_ip = _pop_param(sub_attrs, "gateway_ip", str(cidr[1]))
        dns_ips = _pop_param(sub_attrs, "dns_nameservers", [])
        routes = _pop_param(sub_attrs, "host_routes", [])

        new_subnet = db_api.subnet_create(context, **sub_attrs)

        default_route = None
        for route in routes:
            if netaddr.IPNetwork(route["destination"]) == DEFAULT_ROUTE:
                default_route = route
                gateway_ip = default_route["nexthop"]
            new_subnet["routes"].append(db_api.route_create(
                context, cidr=route["destination"], gateway=route["nexthop"]))
        if default_route is None:
            new_subnet["routes"].append(db_api.route_create(
                context, cidr=str(DEFAULT_ROUTE), gateway=gateway_ip))

        for dns_ip in dns_ips:
            new_subnet["dns_nameservers"].append(db_api.dns_create(
                context, ip=netaddr.IPAddress(dns_ip)))

        subnet_dict = self._make_subnet_dict(new_subnet)
        subnet_dict["gateway_ip"] = gateway_ip
        return subnet_dict

    def update_subnet(self, context, id, subnet):
        """Update values of a subnet.

        : param context: quantum api request context
        : param id: UUID representing the subnet to update.
        : param subnet: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        LOG.info("update_subnet %s for tenant %s" %
                 (id, context.tenant_id))

        subnet_db = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet_db:
            raise exceptions.SubnetNotFound(id=id)

        s = subnet["subnet"]

        dns_ips = s.pop("dns_nameservers", [])
        routes = s.pop("host_routes", [])
        gateway_ip = s.pop("gateway_ip", None)

        if gateway_ip:
            default_route = None
            for route in routes:
                if netaddr.IPNetwork(route["destination"]) == DEFAULT_ROUTE:
                    default_route = route
                    break
            if default_route is None:
                route_model = db_api.route_find(
                    context,
                    cidr=str(DEFAULT_ROUTE),
                    subnet_id=id,
                    scope=db_api.ONE)
                if route_model:
                    db_api.route_update(context,
                                        route_model,
                                        gateway=gateway_ip)
                else:
                    db_api.route_create(context,
                                        cidr=str(DEFAULT_ROUTE),
                                        gateway=gateway_ip,
                                        subnet_id=id)

        subnet = db_api.subnet_update(context, subnet_db, **s)
        subnet_dict = self._make_subnet_dict(subnet)

        if dns_ips:
            dns_models = subnet_db["dns_nameservers"]
            for dns_model in dns_models:
                db_api.dns_delete(context, dns_model)
            subnet_dict["dns_nameservers"] = []
        for dns_ip in dns_ips:
            db_api.dns_create(context,
                              ip=netaddr.IPAddress(dns_ip),
                              subnet_id=subnet["id"])
            subnet_dict["dns_nameservers"].append(dns_ip)

        if routes:
            route_models = subnet_db["routes"]
            for route_model in route_models:
                db_api.route_delete(context, route_model)
            subnet_dict["host_routes"] = []
            subnet_dict["gateway_ip"] = None
        for route in routes:
            db_api.route_create(context,
                                cidr=route["destination"],
                                gateway=route["nexthop"],
                                subnet_id=subnet["id"])
            if netaddr.IPNetwork(route["destination"]) == DEFAULT_ROUTE:
                subnet_dict["gateway_ip"] = route["nexthop"]
            subnet_dict["host_routes"].append(route)

        return subnet_dict

    def get_subnet(self, context, id, fields=None):
        """Retrieve a subnet.

        : param context: quantum api request context
        : param id: UUID representing the subnet to fetch.
        : param fields: a list of strings that are valid keys in a
            subnet dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_subnet %s for tenant %s with fields %s" %
                (id, context.tenant_id, fields))
        subnet = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)

        # Check the network_id against the strategies
        net_id = subnet["network_id"]
        net_id = STRATEGY.get_parent_network(net_id)
        subnet["network_id"] = net_id

        return self._make_subnet_dict(subnet)

    def get_subnets(self, context, filters=None, fields=None):
        """Retrieve a list of subnets.

        The contents of the list depends on the identity of the user
        making the request (as indicated by the context) as well as any
        filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a subnet as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            subnet dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_subnets for tenant %s with filters %s fields %s" %
                (context.tenant_id, filters, fields))
        subnets = db_api.subnet_find(context, **filters)
        return self._make_subnets_list(subnets, fields)

    def get_subnets_count(self, context, filters=None):
        """Return the number of subnets.

        The result depends on the identity of the user making the request
        (as indicated by the context) as well as any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        LOG.info("get_subnets_count for tenant %s with filters %s" %
                (context.tenant_id, filters))
        return db_api.subnet_count_all(context, **filters)

    def _delete_subnet(self, context, subnet):
        if subnet.allocated_ips:
            raise exceptions.SubnetInUse(subnet_id=subnet["id"])
        db_api.subnet_delete(context, subnet)

    def delete_subnet(self, context, id):
        """Delete a subnet.

        : param context: quantum api request context
        : param id: UUID representing the subnet to delete.
        """
        LOG.info("delete_subnet %s for tenant %s" % (id, context.tenant_id))
        subnet = db_api.subnet_find(context, id=id, scope=db_api.ONE)
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)
        self._delete_subnet(context, subnet)

    def create_network(self, context, network):
        """Create a network.

        Create a network which represents an L2 network segment which
        can have a set of subnets and ports associated with it.
        : param context: quantum api request context
        : param network: dictionary describing the network, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_network for tenant %s" % context.tenant_id)
        # Generate a uuid that we're going to hand to the backend and db
        net_uuid = uuidutils.generate_uuid()

        #NOTE(mdietz): probably want to abstract this out as we're getting
        #              too tied to the implementation here
        self.net_driver.create_network(context,
                                       network["network"]["name"],
                                       network_id=net_uuid)

        subnets = []
        if network["network"].get("subnets"):
            subnets = network["network"].pop("subnets")

        network["network"]["id"] = net_uuid
        network["network"]["tenant_id"] = context.tenant_id
        new_net = db_api.network_create(context, **network["network"])

        new_subnets = []
        for sub in subnets:
            sub["subnet"]["network_id"] = new_net["id"]
            sub["subnet"]["tenant_id"] = context.tenant_id
            s = db_api.subnet_create(context, **sub["subnet"])
            new_subnets.append(s)
        new_net["subnets"] = new_subnets
        return self._make_network_dict(new_net)

    def update_network(self, context, id, network):
        """Update values of a network.

        : param context: quantum api request context
        : param id: UUID representing the network to update.
        : param network: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        LOG.info("update_network %s for tenant %s" %
                (id, context.tenant_id))
        net = db_api.network_find(context, id=id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=id)
        net = db_api.network_update(context, net, **network["network"])

        return self._make_network_dict(net)

    def get_network(self, context, id, fields=None):
        """Retrieve a network.

        : param context: quantum api request context
        : param id: UUID representing the network to fetch.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_network %s for tenant %s fields %s" %
                (id, context.tenant_id, fields))

        network = db_api.network_find(context, id=id, scope=db_api.ONE)

        if not network:
            raise exceptions.NetworkNotFound(net_id=id)
        return self._make_network_dict(network)

    def get_networks(self, context, filters=None, fields=None):
        """Retrieve a list of networks.

        The contents of the list depends on the identity of the user
        making the request (as indicated by the context) as well as any
        filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_networks for tenant %s with filters %s, fields %s" %
                (context.tenant_id, filters, fields))
        nets = db_api.network_find(context, **filters)
        return [self._make_network_dict(net) for net in nets]

    def get_networks_count(self, context, filters=None):
        """Return the number of networks.

        The result depends on the identity of the user making the request
        (as indicated by the context) as well as any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        LOG.info("get_networks_count for tenant %s filters %s" %
                (context.tenant_id, filters))
        return db_api.network_count_all(context)

    def delete_network(self, context, id):
        """Delete a network.

        : param context: quantum api request context
        : param id: UUID representing the network to delete.
        """
        LOG.info("delete_network %s for tenant %s" % (id, context.tenant_id))
        net = db_api.network_find(context, id=id, scope=db_api.ONE)
        if not net:
            raise exceptions.NetworkNotFound(net_id=id)
        if net.ports:
            raise exceptions.NetworkInUse(net_id=id)
        self.net_driver.delete_network(context, id)
        for subnet in net["subnets"]:
            self._delete_subnet(context, subnet)
        db_api.network_delete(context, net)

    def create_port(self, context, port):
        """Create a port

        Create a port which is a connection point of a device (e.g., a VM
        NIC) to attach to a L2 Quantum network.
        : param context: quantum api request context
        : param port: dictionary describing the port, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_port for tenant %s" % context.tenant_id)

        mac_address = port["port"].pop("mac_address", None)
        if mac_address and mac_address is attributes.ATTR_NOT_SPECIFIED:
            mac_address = None
        segment_id = port["port"].pop("segment_id", None)

        addresses = []
        port_id = uuidutils.generate_uuid()
        net_id = port["port"]["network_id"]

        net = db_api.network_find(context, id=net_id, shared=True,
                                  segment_id=segment_id, scope=db_api.ONE)
        if not net:
            # Maybe it's a tenant network
            net = db_api.network_find(context, id=net_id, scope=db_api.ONE)
            if not net:
                raise exceptions.NetworkNotFound(net_id=net_id)

        fixed_ips = port["port"].pop("fixed_ips", None)
        if fixed_ips and fixed_ips is not attributes.ATTR_NOT_SPECIFIED:
            for fixed_ip in fixed_ips:
                subnet_id = fixed_ip.get("subnet_id")
                ip_address = fixed_ip.get("ip_address")
                if not (subnet_id and ip_address):
                    raise exceptions.BadRequest(
                        resource="fixed_ips",
                        msg="subnet_id and ip_address required")
                # Note: we don't allow overlapping subnets, thus subnet_id is
                #       ignored.
                addresses.append(self.ipam_driver.allocate_ip_address(
                    context, net["id"], port_id, self.ipam_reuse_after,
                    ip_address=ip_address))
        else:
            addresses.append(self.ipam_driver.allocate_ip_address(
                context, net["id"], port_id, self.ipam_reuse_after))

        mac = self.ipam_driver.allocate_mac_address(context,
                                                    net["id"],
                                                    port_id,
                                                    self.ipam_reuse_after,
                                                    mac_address=mac_address)
        backend_port = self.net_driver.create_port(context, net["id"],
                                                   port_id=port_id)

        port["port"]["network_id"] = net["id"]
        port["port"]["id"] = port_id
        new_port = db_api.port_create(
            context, addresses=addresses, mac_address=mac["address"],
            backend_key=backend_port["uuid"], **port["port"])
        return self._make_port_dict(new_port)

    def update_port(self, context, id, port):
        """Update values of a port.

        : param context: quantum api request context
        : param id: UUID representing the port to update.
        : param port: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        LOG.info("update_port %s for tenant %s" % (id, context.tenant_id))
        port_db = db_api.port_find(context, id=id, scope=db_api.ONE)
        if not port_db:
            raise exceptions.PortNotFound(port_id=id)

        fixed_ips = port["port"].pop("fixed_ips", None)
        if fixed_ips:
            addresses = []
            for fixed_ip in fixed_ips:
                subnet_id = fixed_ip.get("subnet_id")
                ip_address = fixed_ip.get("ip_address")
                if not (subnet_id and ip_address):
                    raise exceptions.BadRequest(
                        resource="fixed_ips",
                        msg="subnet_id and ip_address required")
                # Note: we don't allow overlapping subnets, thus subnet_id is
                #       ignored.
                addresses.append(self.ipam_driver.allocate_ip_address(
                    context, port_db["network_id"], id,
                    self.ipam_reuse_after, ip_address=ip_address))
            port["port"]["addresses"] = addresses

        port = db_api.port_update(context,
                                  port_db,
                                  **port["port"])
        return self._make_port_dict(port)

    def post_update_port(self, context, id, port):
        LOG.info("post_update_port %s for tenant %s" % (id, context.tenant_id))
        port_db = db_api.port_find(context, id=id, scope=db_api.ONE)
        if not port_db:
            raise exceptions.PortNotFound(port_id=id, net_id="")

        if "port" not in port or not port["port"]:
            raise exceptions.BadRequest()
        port = port["port"]

        if "fixed_ips" in port and port["fixed_ips"]:
            for ip in port["fixed_ips"]:
                address = None
                if ip:
                    if "ip_id" in ip:
                        ip_id = ip["ip_id"]
                        address = db_api.ip_address_find(
                            context,
                            id=ip_id,
                            tenant_id=context.tenant_id,
                            scope=db_api.ONE)
                    elif "ip_address" in ip:
                        ip_address = ip["ip_address"]
                        net_address = netaddr.IPAddress(ip_address)
                        address = db_api.ip_address_find(
                            context,
                            ip_address=net_address,
                            network_id=port_db["network_id"],
                            tenant_id=context.tenant_id,
                            scope=db_api.ONE)
                        if not address:
                            address = self.ipam_driver.allocate_ip_address(
                                context,
                                port_db["network_id"],
                                id,
                                self.ipam_reuse_after,
                                ip_address=ip_address)
                else:
                    address = self.ipam_driver.allocate_ip_address(
                        context,
                        port_db["network_id"],
                        id,
                        self.ipam_reuse_after)

            address["deallocated"] = 0

            already_contained = False
            for port_address in port_db["ip_addresses"]:
                if address["id"] == port_address["id"]:
                    already_contained = True
                    break

            if not already_contained:
                port_db["ip_addresses"].append(address)
        return self._make_port_dict(port_db)

    def get_port(self, context, id, fields=None):
        """Retrieve a port.

        : param context: quantum api request context
        : param id: UUID representing the port to fetch.
        : param fields: a list of strings that are valid keys in a
            port dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_port %s for tenant %s fields %s" %
                (id, context.tenant_id, fields))
        results = db_api.port_find(context, id=id, fields=fields,
                                   scope=db_api.ONE)

        if not results:
            raise exceptions.PortNotFound(port_id=id, net_id='')

        return self._make_port_dict(results)

    def get_ports(self, context, filters=None, fields=None):
        """Retrieve a list of ports.

        The contents of the list depends on the identity of the user
        making the request (as indicated by the context) as well as any
        filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a port as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.
        : param fields: a list of strings that are valid keys in a
            port dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_ports for tenant %s filters %s fields %s" %
                (context.tenant_id, filters, fields))
        if filters is None:
            filters = {}
        query = db_api.port_find(context, fields=fields, **filters)
        return self._make_ports_list(query, fields)

    def get_ports_count(self, context, filters=None):
        """Return the number of ports.

        The result depends on the identity of the user making the request
        (as indicated by the context) as well as any filters.
        : param context: quantum api request context
        : param filters: a dictionary with keys that are valid keys for
            a network as listed in the RESOURCE_ATTRIBUTE_MAP object
            in quantum/api/v2/attributes.py.  Values in this dictiontary
            are an iterable containing values that will be used for an exact
            match comparison for that value.  Each result returned by this
            function will have matched one of the values for each key in
            filters.

        NOTE: this method is optional, as it was not part of the originally
              defined plugin API.
        """
        LOG.info("get_ports_count for tenant %s filters %s" %
                (context.tenant_id, filters))
        return db_api.port_count_all(context, **filters)

    def delete_port(self, context, id):
        """Delete a port.

        : param context: quantum api request context
        : param id: UUID representing the port to delete.
        """
        LOG.info("delete_port %s for tenant %s" %
                (id, context.tenant_id))

        port = db_api.port_find(context, id=id, scope=db_api.ONE)
        if not port:
            raise exceptions.PortNotFound(net_id=id)

        backend_key = port["backend_key"]
        mac_address = netaddr.EUI(port["mac_address"]).value
        self.ipam_driver.deallocate_mac_address(context,
                                                mac_address)
        self.ipam_driver.deallocate_ip_address(
            context, port, ipam_reuse_after=self.ipam_reuse_after)
        db_api.port_delete(context, port)
        self.net_driver.delete_port(context, backend_key)

    def disassociate_port(self, context, id, ip_address_id):
        """Disassociates a port from an IP address.

        : param context: quantum api request context
        : param id: UUID representing the port to disassociate.
        : param ip_address_id: UUID representing the IP address to
        disassociate.
        """
        LOG.info("disassociate_port %s for tenant %s ip_address_id %s" %
                (id, context.tenant_id, ip_address_id))
        port = db_api.port_find(context, id=id, ip_address_id=[ip_address_id],
                                scope=db_api.ONE)

        if not port:
            raise exceptions.PortNotFound(port_id=id, net_id='')

        port["ip_addresses"] = [address for address in port["ip_addresses"]
                                if address.id != ip_address_id]

        return self._make_port_dict(port)

    def get_mac_address_range(self, context, id, fields=None):
        """Retrieve a mac_address_range.

        : param context: quantum api request context
        : param id: UUID representing the network to fetch.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_mac_address_range %s for tenant %s fields %s" %
                (id, context.tenant_id, fields))

        mac_address_range = db_api.mac_address_range_find(
            context, id=id, scope=db_api.ONE)

        if not mac_address_range:
            raise quark_exceptions.MacAddressRangeNotFound(
                mac_address_range_id=id)
        return self._make_mac_range_dict(mac_address_range)

    def get_mac_address_ranges(self, context):
        LOG.info("get_mac_address_ranges for tenant %s" % context.tenant_id)
        ranges = db_api.mac_address_range_find(context)
        return [self._make_mac_range_dict(m) for m in ranges]

    def create_mac_address_range(self, context, mac_range):
        LOG.info("create_mac_address_range for tenant %s" % context.tenant_id)
        cidr = mac_range["mac_address_range"]["cidr"]
        cidr, first_address, last_address = self._to_mac_range(cidr)
        new_range = db_api.mac_address_range_create(
            context, cidr=cidr, first_address=first_address,
            last_address=last_address, next_auto_assign_mac=first_address)
        return self._make_mac_range_dict(new_range)

    def _to_mac_range(self, val):
        cidr_parts = val.split("/")
        prefix = cidr_parts[0]
        prefix = prefix.replace(':', '')
        prefix = prefix.replace('-', '')
        prefix_length = len(prefix)
        if prefix_length < 6 or prefix_length > 10:
            raise quark_exceptions.InvalidMacAddressRange(cidr=val)

        diff = 12 - len(prefix)
        if len(cidr_parts) > 1:
            mask = int(cidr_parts[1])
        else:
            mask = 48 - diff * 4
        mask_size = 1 << (48 - mask)
        prefix = "%s%s" % (prefix, "0" * diff)
        try:
            cidr = "%s/%s" % (str(netaddr.EUI(prefix)).replace("-", ":"), mask)
        except netaddr.AddrFormatError:
            raise quark_exceptions.InvalidMacAddressRange(cidr=val)
        prefix_int = int(prefix, base=16)
        return cidr, prefix_int, prefix_int + mask_size

    def _delete_mac_address_range(self, context, mac_address_range):
        if mac_address_range.allocated_macs:
            raise quark_exceptions.MacAddressRangeInUse(
                mac_address_range_id=mac_address_range["id"])
        db_api.mac_address_range_delete(context, mac_address_range)

    def delete_mac_address_range(self, context, id):
        """Delete a mac_address_range.

        : param context: quantum api request context
        : param id: UUID representing the mac_address_range to delete.
        """
        LOG.info("delete_mac_address_range %s for tenant %s" %
                 (id, context.tenant_id))
        mar = db_api.mac_address_range_find(context, id=id, scope=db_api.ONE)
        if not mar:
            raise quark_exceptions.MacAddressRangeNotFound(
                mac_address_range_id=id)
        self._delete_mac_address_range(context, mar)

    def get_route(self, context, id):
        LOG.info("get_route %s for tenant %s" % (id, context.tenant_id))
        route = db_api.route_find(context, id=id)
        if not route:
            raise quark_exceptions.RouteNotFound(route_id=id)
        return self._make_route_dict(route)

    def get_routes(self, context):
        LOG.info("get_routes for tenant %s" % context.tenant_id)
        routes = db_api.route_find(context)
        return [self._make_route_dict(r) for r in routes]

    def create_route(self, context, route):
        LOG.info("create_route for tenant %s" % context.tenant_id)
        route = route["route"]
        subnet_id = route["subnet_id"]
        subnet = db_api.subnet_find(context, id=id)
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=subnet_id)

        # TODO(anyone): May need to denormalize the cidr values to achieve
        #               single db lookup
        route_cidr = netaddr.IPNetwork(route["cidr"])
        subnet_routes = db_api.route_find(context, subnet_id=subnet_id)
        for sub_route in subnet_routes:
            sub_route_cidr = netaddr.IPNetwork(sub_route["cidr"])
            if route_cidr in sub_route_cidr or sub_route_cidr in route_cidr:
                raise quark_exceptions.RouteConflict(route_id=sub_route["id"],
                                                     cidr=str(route_cidr))

        new_route = db_api.route_create(context, **route)
        return self._make_route_dict(new_route)

    def delete_route(self, context, id):
        #TODO(mdietz): This is probably where we check to see that someone is
        #              admin and only filter on tenant if they aren't. Correct
        #              for all the above later
        LOG.info("delete_route %s for tenant %s" % (id, context.tenant_id))
        route = db_api.route_find(context, id)
        if not route:
            raise quark_exceptions.RouteNotFound(route_id=id)
        db_api.route_delete(context, route)

    def get_ip_addresses(self, context, **filters):
        LOG.info("get_ip_addresses for tenant %s" % context.tenant_id)
        addrs = db_api.ip_address_find(context, **filters)
        return [self._make_ip_dict(ip) for ip in addrs]

    def get_ip_address(self, context, id):
        LOG.info("get_ip_address %s for tenant %s" %
                (id, context.tenant_id))
        addr = db_api.ip_address_find(context, id=id)
        if not addr:
            raise quark_exceptions.IpAddressNotFound(addr_id=id)
        return self._make_ip_dict(addr)

    def create_ip_address(self, context, ip_address):
        LOG.info("create_ip_address for tenant %s" % context.tenant_id)

        port = None
        ip_dict = ip_address["ip_address"]
        port_ids = ip_dict.get('port_ids')
        network_id = ip_dict.get('network_id')
        device_ids = ip_dict.get('device_ids')
        ip_version = ip_dict.get('version')
        ip_address = ip_dict.get('ip_address')

        ports = []
        if network_id and device_ids:
            for device_id in device_ids:
                port = db_api.port_find(
                    context, network_id=network_id, device_id=device_id,
                    tenant_id=context.tenant_id, scope=db_api.ONE)
                ports.append(port)
        elif port_ids:
            for port_id in port_ids:
                port = db_api.port_find(context, id=port_id,
                                        tenant_id=context.tenant_id,
                                        scope=db_api.ONE)
                ports.append(port)

        if not ports:
            raise exceptions.PortNotFound(port_id=port_ids,
                                          net_id=network_id)

        address = self.ipam_driver.allocate_ip_address(
            context,
            port['network_id'],
            port['id'],
            self.ipam_reuse_after,
            ip_version,
            ip_address)

        for port in ports:
            port["ip_addresses"].append(address)

        return self._make_ip_dict(address)

    def update_ip_address(self, context, id, ip_address):
        LOG.info("update_ip_address %s for tenant %s" %
                (id, context.tenant_id))

        address = db_api.ip_address_find(
            context, id=id, tenant_id=context.tenant_id, scope=db_api.ONE)

        if not address:
            raise exceptions.NotFound(
                message="No IP address found with id=%s" % id)

        old_ports = address['ports']
        port_ids = ip_address['ip_address'].get('port_ids')
        if port_ids is None:
            return self._make_ip_dict(address)

        for port in old_ports:
            port['ip_addresses'].remove(address)

        if port_ids:
            ports = db_api.port_find(
                context, tenant_id=context.tenant_id, id=port_ids,
                scope=db_api.ALL)

            # NOTE: could be considered inefficient because we're converting
            #       to a list to check length. Maybe revisit
            if len(ports) != len(port_ids):
                raise exceptions.NotFound(
                    message="No ports not found with ids=%s" % port_ids)
            for port in ports:
                port['ip_addresses'].extend([address])
        return self._make_ip_dict(address)

    def create_security_group(self, context, security_group):
        LOG.info("create_security_group for tenant %s" %
                (context.tenant_id))
        g = security_group["security_group"]
        group = db_api.security_group_create(context, **g)
        return self._make_security_group_dict(group)

    def create_security_group_rule(self, context, security_group_rule):
        LOG.info("create_security_group for tenant %s" %
                (context.tenant_id))
        r = security_group_rule["security_group_rule"]
        group_id = r["security_group_id"]
        group = db_api.security_group_find(context, id=group_id)
        if not group:
            raise sg_ext.SecurityGroupNotFound(group_id=group_id)
        rule = db_api.security_group_rule_create(context, **r)
        return self._make_security_group_rule_dict(rule)

    def delete_security_group(self, context, id):
        LOG.info("delete_security_group %s for tenant %s" %
                (id, context.tenant_id))
        group = db_api.security_group_find(context, id=id, scope=db_api.ONE)
        if not group:
            raise sg_ext.SecurityGroupNotFound(group_id=id)
        db_api.security_group_delete(context, group)

    def delete_security_group_rule(self, context, id):
        LOG.info("delete_security_group %s for tenant %s" %
                (id, context.tenant_id))
        rule = db_api.security_group_rule_find(context, id=id,
                                               scope=db_api.ONE)
        if not rule:
            raise sg_ext.SecurityGroupRuleNotFound(group_id=id)
        db_api.security_group_rule_delete(context, rule)

    def get_security_group(self, context, id, fields=None):
        LOG.info("get_security_group %s for tenant %s" %
                (id, context.tenant_id))
        group = db_api.security_group_find(context, id=id, scope=db_api.ONE)
        if not group:
            raise sg_ext.SecurityGroupNotFound(group_id=id)
        return self._make_security_group_dict(group, fields)

    def get_security_group_rule(self, context, id, fields=None):
        LOG.info("get_security_group_rule %s for tenant %s" %
                (id, context.tenant_id))
        rule = db_api.security_group_rule_find(context, id=id,
                                               scope=db_api.ONE)
        if not rule:
            raise sg_ext.SecurityGroupRuleNotFound(rule_id=id)
        return self._make_security_group_rule_dict(rule, fields)

    def get_security_groups(self, context, filters=None, fields=None,
                            sorts=None, limit=None, marker=None,
                            page_reverse=False):
        LOG.info("get_security_groups for tenant %s" %
                (context.tenant_id))
        groups = db_api.security_group_find(context, filters=filters)
        return [self._make_security_group_dict(group) for group in groups]

    def get_security_group_rules(self, context, filters=None, fields=None,
                                 sorts=None, limit=None, marker=None,
                                 page_reverse=False):
        LOG.info("get_security_group_rules for tenant %s" %
                (context.tenant_id))
        rules = db_api.security_group_rule_find(context, filters=filters)
        return [self._make_security_group_rule_dict(rule) for rule in rules]

    def update_security_group(self, context, id, security_group):
        raise NotImplementedError()
