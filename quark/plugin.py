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

import netaddr
from sqlalchemy import func as sql_func
from oslo.config import cfg

from quantum import quantum_plugin_base_v2
from quantum.common import exceptions
from quantum.db import api as db_api
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils

from quark.api import extensions
from quark.db import models
from quark import exceptions as quark_exceptions

LOG = logging.getLogger("quantum.quark")
CONF = cfg.CONF

quark_opts = [
    cfg.StrOpt('net_driver',
               default='quark.drivers.base.BaseDriver',
               help=_('The client to use to talk to the backend')),
    cfg.StrOpt('ipam_driver', default='quark.ipam.QuarkIpam',
               help=_('IPAM Implementation to use')),
    cfg.BoolOpt('ipam_reuse_after', default=7200,
                help=_("Time in seconds til IP and MAC reuse"
                       "after deallocation.")),
    cfg.StrOpt('net_driver_cfg', default='/etc/quantum/quark.ini',
               help=_("Path to the config for the net driver"))
]

CONF.register_opts(quark_opts, "QUARK")
if 'api_extensions_path' in CONF:
    CONF.set_override('api_extensions_path', ":".join(extensions.__path__))


class Plugin(quantum_plugin_base_v2.QuantumPluginBaseV2):
    # NOTE(mdietz): I hate this
    supported_extension_aliases = ["mac_address_ranges", "routes",
                                   "ip_addresses"]

    def __init__(self):
        db_api.configure_db()
        self.net_driver = (importutils.import_class(CONF.QUARK.net_driver))()
        self.net_driver.load_config(CONF.QUARK.net_driver_cfg)
        self.ipam_driver = (importutils.import_class(CONF.QUARK.ipam_driver))()
        self.ipam_reuse_after = CONF.QUARK.ipam_reuse_after
        models.BASEV2.metadata.create_all(db_api._ENGINE)

    def _make_network_dict(self, network, fields=None):
        res = {'id': network.get('id'),
               'name': network.get('name'),
               'tenant_id': network.get('tenant_id'),
               'admin_state_up': network.get('admin_state_up'),
               'status': network.get('status'),
               'shared': network.get('shared'),
               #TODO(mdietz): this is the expected return. Then the client
               #              foolishly turns around and asks for the entire
               #              subnet list anyway! Plz2fix
               'subnets': [s["id"] for s in network.get("subnets", [])]}
               #'subnets': [self._make_subnet_dict(subnet)
               #            for subnet in network.get('subnets', [])]}
        return res

    def _subnet_dict(self, subnet, fields=None):
        # TODO(mdietz): this is a hack to get nova to boot. We want to get the
        #               "default" route out of the database and use that
        gateway_ip = "0.0.0.0"
        subnet["allocation_pools"] = subnet.get("allocation_pools") or {}
        subnet["dns_nameservers"] = subnet.get("dns_nameservers") or {}
        return {"id": subnet.get('id'),
                "name": subnet.get('id'),
                "tenant_id": subnet.get('tenant_id'),
                "network_id": subnet.get('network_id'),
                "ip_version": subnet.get('ip_version'),
                "cidr": subnet.get('cidr'),
                "enable_dhcp": subnet.get('enable_dhcp'),
                "gateway_ip": gateway_ip}

    def _make_subnet_dict(self, subnet, fields=None):
        res = self._subnet_dict(subnet, fields)
        res["routes"] = [self._make_route_dict(r) for r in subnet["routes"]]
               #'dns_nameservers': [dns.get('address')
               #                    for dns in subnet.get('dns_nameservers')],
               #'host_routes': [{'destination': route.get('destination'),
               #                 'nexthop': route.get('nexthop')}
               #                for route in subnet.get('routes', [])],
               #'shared': subnet.get('shared')
               #}
               #'allocation_pools': [{'start': pool.get('first_ip'),
               #                      'end': pool.get('last_ip')}
               #                for pool in subnet.get('allocation_pools')],
               #}
        #if subnet.get('gateway_ip'):
        #    res['gateway_ip'] = subnet.get('gateway_ip')
        return res

    def _port_dict(self, port, fields):
        mac = ""
        if port.get("mac_address"):
            mac = str(netaddr.EUI(port["mac_address"])).replace("-", ":")
        res = {"id": port.get("id"),
               "name": port.get('id'),
               "network_id": port.get("network_id"),
               "tenant_id": port.get('tenant_id'),
               "mac_address": mac,
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
        res = self._port_dict(port, fields)
        res["fixed_ips"] = [self._make_port_address_dict(ip)
                            for ip in port["ip_addresses"]]
        return res

    def _make_ports_list(self, query, fields=None):
        ports = {}
        for port_dict, addr_dict in query:
            port_id = port_dict["id"]
            if port_id not in ports:
                ports[port_id] = self._port_dict(port_dict, fields)
                ports[port_id]["fixed_ips"] = []
            if addr_dict:
                ports[port_id]["fixed_ips"].append(
                    self._make_port_address_dict(addr_dict))
        return ports.values()

    def _make_subnets_list(self, query, fields=None):
        subnets = {}
        for subnet_dict, route_dict in query:
            subnet_id = subnet_dict["id"]
            if subnet_id not in subnets:
                subnets[subnet_id] = {}
                subnets[subnet_id]["routes"] = []
                subnets[subnet_id] = self._subnet_dict(subnet_dict, fields)
            if route_dict:
                subnets[subnet_id]["routes"].append(
                    self._make_route_dict(route_dict))
        return subnets.values()

    def _make_mac_range_dict(self, mac_range):
        return {"id": mac_range["id"],
                "cidr": mac_range["cidr"]}

    def _make_route_dict(self, route):
        return {"id": route["id"],
                "cidr": route["cidr"],
                "gateway": route["gateway"],
                "subnet_id": route["subnet_id"]}

    def _make_ip_dict(self, address):
        return {"id": address["id"],
                "network_id": address["network_id"],
                "address": address.formatted(),
                "port_id": address["port_id"],
                "subnet_id": address["subnet_id"]}

    def _create_subnet(self, context, subnet, session=None):
        s = models.Subnet()
        s.update(subnet["subnet"])
        s["tenant_id"] = context.tenant_id
        session.add(s)
        return s

    def create_subnet(self, context, subnet):
        """
        Create a subnet, which represents a range of IP addresses
        that can be allocated to devices
        : param context: quantum api request context
        : param subnet: dictionary describing the subnet, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_subnet for tenant %s" % context.tenant_id)
        session = context.session
        new_subnet = self._create_subnet(context, subnet, session)
        session.flush()
        subnet_dict = self._make_subnet_dict(new_subnet)
        return subnet_dict

    def update_subnet(self, context, id, subnet):
        """
        Update values of a subnet.
        : param context: quantum api request context
        : param id: UUID representing the subnet to update.
        : param subnet: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.

        Raises NotImplemented, as there are no attributes one can safely
        update on a subnet
        """
        raise NotImplemented()

    def get_subnet(self, context, id, fields=None):
        """
        Retrieve a subnet.
        : param context: quantum api request context
        : param id: UUID representing the subnet to fetch.
        : param fields: a list of strings that are valid keys in a
            subnet dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_subnet %s for tenant %s with fields %s" %
                (id, context.tenant_id, fields))
        results = context.session.query(models.Subnet, models.Route).\
            outerjoin(models.Route).\
            filter(models.Subnet.id == id).all()
        if not results:
            raise exceptions.SubnetNotFound(subnet_id=id)
        subnet = {}
        subnet.update(results[0][0])
        subnet["routes"] = []
        for _, route in results:
            if route:
                subnet["routes"].append(route)
        return self._make_subnet_dict(subnet)

    def get_subnets(self, context, filters=None, fields=None):
        """
        Retrieve a list of subnets.  The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.
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
        query = context.session.query(models.Subnet, models.Route).\
            outerjoin(models.Route)
        if filters.get("network_id"):
            query = query.filter(
                models.Subnet.network_id == filters["network_id"])
        return self._make_subnets_list(query, fields)

    def get_subnets_count(self, context, filters=None):
        """
        Return the number of subnets.  The result depends on the identity of
        the user making the request (as indicated by the context) as well as
        any filters.
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
        query = context.session.query(sql_func.count(models.Subnet.id))
        if filters.get("network_id"):
            query = query.filter(
                models.Subnet.network_id == filters["network_id"])
        return query.scalar()

    def _delete_subnet(self, subnet, session):
        if subnet.allocated_ips:
            raise exceptions.SubnetInUse(subnet_id=id)
        session.delete(subnet)

    def delete_subnet(self, context, id):
        """
        Delete a subnet.
        : param context: quantum api request context
        : param id: UUID representing the subnet to delete.
        """
        LOG.info("delete_subnet %s for tenant %s with filters %s" %
                (id, context.tenant_id))
        subnet = context.session.query(models.Subnet).\
            filter(models.Subnet.id == id).\
            first()
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)

        self._delete_subnet(subnet, context.session)
        context.session.flush()

    def create_network(self, context, network):
        """
        Create a network, which represents an L2 network segment which
        can have a set of subnets and ports associated with it.
        : param context: quantum api request context
        : param network: dictionary describing the network, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_network for tenant %s" % context.tenant_id)
        with context.session.begin(subtransactions=True):
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
            new_net = models.Network(id=net_uuid, tenant_id=context.tenant_id)
            new_net.update(network["network"])

            for sub in subnets:
                sub["subnet"]["network_id"] = new_net["id"]
                self._create_subnet(context, sub, context.session)
            context.session.add(new_net)

        return self._make_network_dict(new_net)

    def update_network(self, context, id, network):
        """
        Update values of a network.
        : param context: quantum api request context
        : param id: UUID representing the network to update.
        : param network: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        LOG.info("update_network %s for tenant %s with filters %s" %
                (id, context.tenant_id))
        with context.session.begin(subtransactions=True):
            net = context.session.query(models.Network).\
                filter(models.Network.id == id).\
                first()
            if not network:
                raise exceptions.NetworkNotFound(net_id=id)
            net.update(network["network"])
            context.session.add(net)

        return self._make_network_dict(net)

    def get_network(self, context, id, fields=None):
        """
        Retrieve a network.
        : param context: quantum api request context
        : param id: UUID representing the network to fetch.
        : param fields: a list of strings that are valid keys in a
            network dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_network %s for tenant %s fields %s" %
                (id, context.tenant_id, fields))
        query = context.session.query(models.Network)
        network = query.filter(models.Network.id == id).first()
        if not network:
            raise exceptions.NetworkNotFound(net_id=id)
        return self._make_network_dict(network)

    def get_networks(self, context, filters=None, fields=None):
        """
        Retrieve a list of networks.  The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.
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
        query = context.session.query(models.Network)
        # TODO(mdietz): we don't support "shared" networks yet. The concept
        #               is broken
        if filters.get("shared") and True in filters["shared"]:
            return []
        query = query.filter(models.Network.tenant_id == context.tenant_id)
        if "id" in filters:
            query = query.filter(models.Network.id.in_(filters["id"]))
        nets = query.all()

        return [self._make_network_dict(net) for net in nets]

    def get_networks_count(self, context, filters=None):
        """
        Return the number of networks.  The result depends on the identity
        of the user making the request (as indicated by the context) as well
        as any filters.
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
        query = context.session.query(sql_func.count(models.Network.id))
        return query.filter(models.Network.tenant_id == context.tenant_id).\
            scalar()

    def delete_network(self, context, id):
        """
        Delete a network.
        : param context: quantum api request context
        : param id: UUID representing the network to delete.
        """
        LOG.info("delete_network %s for tenant %s" % (id, context.tenant_id))
        session = context.session
        with session.begin():
            net = session.query(models.Network).\
                filter(models.Network.id == id).\
                filter(models.Network.tenant_id == context.tenant_id).\
                first()
            if not net:
                raise exceptions.NetworkNotFound(net_id=id)
            if net.ports:
                raise exceptions.NetworkInUse(net_id=id)
            self.net_driver.delete_network(context, id)
            for subnet in net["subnets"]:
                self._delete_subnet(subnet, session)
            session.delete(net)

    def create_port(self, context, port):
        """
        Create a port, which is a connection point of a device (e.g., a VM
        NIC) to attach to a L2 Quantum network.
        : param context: quantum api request context
        : param port: dictionary describing the port, with keys
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.  All keys will be populated.
        """
        LOG.info("create_port for tenant %s" % context.tenant_id)
        session = context.session

        #TODO(mdietz): do something clever with these
        garbage = ["fixed_ips", "mac_address", "device_owner"]
        for k in garbage:
            if k in port["port"]:
                port["port"].pop(k)

        addresses = []
        with session.begin():
            port_id = uuidutils.generate_uuid()
            net_id = port["port"]["network_id"]

            net = session.query(models.Network).\
                filter(models.Network.id == net_id).\
                filter(models.Network.tenant_id == context.tenant_id).\
                first()
            if not net:
                raise exceptions.NetworkNotFound(net_id=net_id)

            addresses.append(
                self.ipam_driver.allocate_ip_address(session,
                                                     net_id,
                                                     port_id,
                                                     context.tenant_id,
                                                     self.ipam_reuse_after))
            mac = self.ipam_driver.allocate_mac_address(session,
                                                        net_id,
                                                        port_id,
                                                        context.tenant_id,
                                                        self.ipam_reuse_after)
            backend_port = self.net_driver.create_port(context, net_id,
                                                       port_id=port_id)

            new_port = models.Port()
            new_port.update(port["port"])
            new_port["id"] = port_id
            new_port["backend_key"] = backend_port["uuid"]
            new_port["addresses"] = addresses
            new_port["mac_address"] = mac["address"]
            new_port["tenant_id"] = context.tenant_id
            new_port["ip_addresses"].extend(addresses)

            session.add(mac)
            session.add(new_port)

        new_port["mac_address"] = str(netaddr.EUI(new_port["mac_address"],
                                      dialect=netaddr.mac_unix))
        LOG.debug("Port created %s" % new_port)
        return self._make_port_dict(new_port)

    def update_port(self, context, id, port):
        """
        Update values of a port.
        : param context: quantum api request context
        : param id: UUID representing the port to update.
        : param port: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        raise NotImplemented()

    def get_port(self, context, id, fields=None):
        """
        Retrieve a port.
        : param context: quantum api request context
        : param id: UUID representing the port to fetch.
        : param fields: a list of strings that are valid keys in a
            port dictionary as listed in the RESOURCE_ATTRIBUTE_MAP
            object in quantum/api/v2/attributes.py. Only these fields
            will be returned.
        """
        LOG.info("get_port %s for tenant %s fields %s" %
                (id, context.tenant_id, fields))
        query = context.session.query(models.Port)
        result = query.filter(models.Port.id == id).first()

        if not result:
            raise exceptions.PortNotFound(port_id=id, net_id='')

        return self._make_port_dict(result)

    def _ports_query(self, context, filters, query, fields=None):
        if filters.get("id"):
            query = query.filter(
                models.Port.id.in_(filters["id"]))

        if filters.get("name"):
            query = query.filter(
                models.Port.id.in_(filters["name"]))

        if filters.get("network_id"):
            query = query.filter(
                models.Port.network_id.in_(filters["network_id"]))

        if filters.get("device_id"):
            query = query.filter(models.Port.device_id.in_(
                filters["device_id"]))

        if filters.get("mac_address"):
            query = query.filter(
                models.Port.mac_address.in_(filters["mac_address"]))

        if filters.get("tenant_id"):
            query = query.filter(
                models.Port.tenant_id.in_(filters["tenant_id"]))

        return query

    def get_ports(self, context, filters=None, fields=None):
        """
        Retrieve a list of ports.  The contents of the list depends on
        the identity of the user making the request (as indicated by the
        context) as well as any filters.
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
        query = context.session.query(models.Port, models.IPAddress).\
            outerjoin(models.Port.ip_addresses)
        query = self._ports_query(context, filters, fields=fields, query=query)
        return self._make_ports_list(query, fields)

    def get_ports_count(self, context, filters=None):
        """
        Return the number of ports.  The result depends on the identity of
        the user making the request (as indicated by the context) as well as
        any filters.
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
        query = context.session.query(sql_func.count(models.Port.id))
        return self._ports_query(context, filters, query=query).scalar()

    def delete_port(self, context, id):
        """
        Delete a port.
        : param context: quantum api request context
        : param id: UUID representing the port to delete.
        """
        LOG.info("delete_port %s for tenant %s" %
                (id, context.tenant_id))
        session = context.session
        port = session.query(models.Port).\
            filter(models.Port.id == id).\
            filter(models.Port.tenant_id == context.tenant_id).\
            first()
        if not port:
            raise exceptions.NetworkNotFound(net_id=id)

        backend_key = port["backend_key"]
        mac_address = netaddr.EUI(port["mac_address"]).value
        self.ipam_driver.deallocate_mac_address(session,
                                                mac_address,)
        self.ipam_driver.deallocate_ip_address(
            session, id, ipam_reuse_after=self.ipam_reuse_after)
        session.delete(port)
        session.flush()
        self.net_driver.delete_port(context, backend_key)

    def get_mac_address_ranges(self, context):
        LOG.info("get_mac_address_ranges for tenant %s" % context.tenant_id)
        ranges = context.session.query(models.MacAddressRange).all()
        return [self._make_mac_range_dict(m) for m in ranges]

    def create_mac_address_range(self, context, mac_range):
        LOG.info("create_mac_address_range for tenant %s" % context.tenant_id)
        new_range = models.MacAddressRange()
        cidr = mac_range["mac_address_range"]["cidr"]
        cidr, first_address, last_address = self._to_mac_range(cidr)
        new_range["cidr"] = cidr
        new_range["first_address"] = first_address
        new_range["last_address"] = last_address
        new_range["tenant_id"] = context.tenant_id
        context.session.add(new_range)
        context.session.flush()
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
        prefix_int = int(prefix, base=16)
        cidr = "%s/%s" % (str(netaddr.EUI(prefix)).replace("-", ":"), mask)
        return cidr, prefix_int, prefix_int + mask_size

    def get_route(self, context, id):
        LOG.info("get_route %s for tenant %s" % (id, context.tenant_id))
        route = context.session.query(models.Route).\
            filter(models.Route.tenant_id == context.tenant_id).\
            filter(models.Route.id == id).\
            first()
        if not route:
            raise quark_exceptions.RouteNotFound(route_id=id)
        return self._make_route_dict(route)

    def get_routes(self, context):
        LOG.info("get_routes for tenant %s" % context.tenant_id)
        routes = context.session.query(models.Route).\
            filter(models.Route.tenant_id == context.tenant_id).\
            all()
        return [self._make_route_dict(r) for r in routes]

    def create_route(self, context, route):
        LOG.info("create_route for tenant %s" % context.tenant_id)
        route = route["route"]
        subnet_id = route["subnet_id"]
        subnet = context.session.query(models.Subnet).\
            filter(models.Subnet.id == subnet_id).\
            filter(models.Subnet.tenant_id == context.tenant_id).\
            first()
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=subnet_id)

        new_route = models.Route()
        new_route.update(route)
        new_route["tenant_id"] = context.tenant_id
        context.session.add(new_route)
        context.session.flush()
        return self._make_route_dict(new_route)

    def delete_route(self, context, id):
        #TODO(mdietz): This is probably where we check to see that someone is
        #              admin and only filter on tenant if they aren't. Correct
        #              for all the above later
        LOG.info("delete_route %s for tenant %s" % (id, context.tenant_id))
        route = context.session.query(models.Route).\
            filter(models.Route.id == id).\
            filter(models.Route.tenant_id == context.tenant_id).\
            first()
        if not route:
            raise quark_exceptions.RouteNotFound(route_id=id)
        context.session.delete(route)
        context.session.flush()

    def get_ip_addresses(self, context):
        LOG.info("get_ip_addresses for tenant %s" % context.tenant_id)
        addrs = context.session.query(models.IPAddress).\
            filter(models.IPAddress.tenant_id == context.tenant_id).\
            all()
        return [self._make_ip_dict(ip) for ip in addrs]

    def get_ip_address(self, context, id):
        LOG.info("get_ip_address %s for tenant %s" %
                (id, context.tenant_id))
        addr = context.session.query(models.IPAddress).\
            filter(models.IPAddress.tenant_id == context.tenant_id).\
            filter(models.IPAddress.id == id).\
            first()
        return self._make_ip_dict(addr)

    def create_ip_address(self, context, ip_address):
        LOG.info("create_ip_address for tenant %s" % context.tenant_id)

        port = None
        port_id = ip_address['ip_address'].get('port_id')
        network_id = ip_address['ip_address'].get('network_id')
        device_id = ip_address['ip_address'].get('device_id')
        if network_id and device_id:
            query = context.session.query(models.Port)
            query = query.filter_by(network_id=network_id)
            query = query.filter_by(device_id=device_id)
            port = query.first()
        elif port_id:
            query = context.session.query(models.Port)
            query = query.filter_by(id=port_id)
            port = query.first()

        if not port:
            raise exceptions.PortNotFound(id=port_id,
                                          net_id=network_id,
                                          device_id=device_id)

    def update_ip_address(self, context, id, ip_address):
        raise NotImplemented()
