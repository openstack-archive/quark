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
v2 Quantum Plug-in API Quark Implementation
"""

from sqlalchemy import func as sql_func

from quantum.api.v2 import attributes as q_attr
from quantum import quantum_plugin_base_v2
from quantum.common import exceptions
from quantum.db import api as db_api
from quantum.openstack.common import cfg
from quantum.openstack.common import importutils
from quantum.openstack.common import log as logging
from quantum.openstack.common import uuidutils

from quark.db import models

LOG = logging.getLogger("quantum")
CONF = cfg.CONF

quark_opts = [
    cfg.StrOpt('nvp_driver', default='aicq.QuantumPlugin.NvpPlugin',
               help=_('The client to use to talk to NVP')),
    cfg.StrOpt('nvp_driver_cfg', default='/etc/quantum/quark.ini',
               help=_("Path to the config for the NVP driver"))
]

CONF.register_opts(quark_opts, "QUARK")

#NOTE(mdietz): hacking this for now because disallowing subnets on a network
#              create is absurd. Might be useful to implement the ability
#              upstream to add a "mask" on the attributes to override


q_attr.RESOURCE_ATTRIBUTE_MAP["networks"]["subnets"]["allow_post"] = True


class Plugin(quantum_plugin_base_v2.QuantumPluginBaseV2):
    def __init__(self):
        db_api.configure_db()
        self.nvp_driver = (importutils.import_class(CONF.QUARK.nvp_driver)
                                        (configfile=CONF.QUARK.nvp_driver_cfg))

    def _make_network_dict(self, network, fields=None):
        res = {'id': network.get('id'),
               'name': network.get('name'),
               'tenant_id': network.get('tenant_id'),
               'admin_state_up': network.get('admin_state_up'),
               'status': network.get('status'),
               'shared': network.get('shared'),
               'subnets': [self._make_subnet_dict(subnet)
                           for subnet in network.get('subnets', [])]}
        return res

    def _make_subnet_dict(self, subnet, fields=None):
        subnet['allocation_pools'] = subnet.get('allocation_pools') or {}
        subnet['dns_nameservers'] = subnet.get('dns_nameservers') or {}

        res = {'id': subnet.get('id'),
               'name': subnet.get('name'),
               'tenant_id': subnet.get('tenant_id'),
               'network_id': subnet.get('network_id'),
               'ip_version': subnet.get('ip_version'),
               'cidr': subnet.get('cidr'),
               'allocation_pools': [{'start': pool.get('first_ip'),
                                     'end': pool.get('last_ip')}
                                   for pool in subnet.get('allocation_pools')],
               'gateway_ip': subnet.get('gateway_ip'),
               'enable_dhcp': subnet.get('enable_dhcp'),
               'dns_nameservers': [dns.get('address')
                                   for dns in subnet.get('dns_nameservers')],
               'host_routes': [{'destination': route.get('destination'),
                                'nexthop': route.get('nexthop')}
                               for route in subnet.get('routes', [])],
               'shared': subnet.get('shared')
               }
        if subnet.get('gateway_ip'):
            res['gateway_ip'] = subnet.get('gateway_ip')
        return res

    def _make_port_dict(self, port, fields=None):
        port["fixed_ips"] = port.get("fixed_ips") or {}
        res = {"id": port.get("id"),
               'name': port.get('name'),
               "network_id": port.get("network_id"),
               'tenant_id': port.get('tenant_id'),
               "mac_address": port.get("mac_address"),
               "admin_state_up": port.get("admin_state_up"),
               "status": port.get("status"),
               "fixed_ips": [{'subnet_id': ip.get("subnet_id"),
                              'ip_address': ip.get("ip_address")}
                             for ip in port.get("fixed_ips")],
               "device_id": port.get("device_id"),
               "device_owner": port.get("device_owner")}
        return res

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
        session = context.session
        new_subnet = self._create_subnet(context, subnet, session)
        session.flush()
        return self._make_subnet_dict(new_subnet)

    def update_subnet(self, context, id, subnet):
        """
        Update values of a subnet.
        : param context: quantum api request context
        : param id: UUID representing the subnet to update.
        : param subnet: dictionary with keys indicating fields to update.
            valid keys are those that have a value of True for 'allow_put'
            as listed in the RESOURCE_ATTRIBUTE_MAP object in
            quantum/api/v2/attributes.py.
        """
        subnet = {'id': id}
        return self._make_subnet_dict(subnet)

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
        subnet = context.session.query(models.Subnet).\
                    filter(models.Subnet.id == id).\
                    first()
        if not subnet:
            raise exceptions.SubnetNotFound(subnet_id=id)

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
        query = context.session.query(models.Subnet)
        if filters.get("network_id"):
            query = query.filter(
                    models.Subnet.network_id == filters["network_id"])
        return [self._make_subnet_dict(s) for s in query.all()]

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
        query = context.session.query(sql_func.count(models.Subnet))
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
        with context.session.begin(subtransactions=True):
            # Generate a uuid that we're going to hand to NVP and the database
            net_uuid = uuidutils.generate_uuid()

            #NOTE(mdietz): probably want to abstract this out as we're getting
            #              too tied to the implementation here
            tags = [{"tag": net_uuid, "scope": "quantum_net_id"}]
            self.nvp_driver.create_network(context.tenant_id,
                                           network["network"]["name"],
                                           tags=tags)

            if network["network"].get("subnets"):
                subnets = network["network"].pop("subnets")
            new_net = models.Network(id=net_uuid)
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
        network = {'id': id}
        return self._make_network_dict(network)

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
        query = context.session.query(models.Network)
        nets = query.filter(models.Network.tenant_id == context.tenant_id).\
                     all()
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
        query = context.session.query(sql_func.count(models.Network))
        return query.filter(models.Network.tenant_id == context.tenant_id).\
                     scalar()

    def delete_network(self, context, id):
        """
        Delete a network.
        : param context: quantum api request context
        : param id: UUID representing the network to delete.
        """
        session = context.session
        with session.begin():
            net = session.query(models.Network).\
                        filter(models.Network.id == id).\
                        first()
            if not net:
                raise exceptions.NetworkNotFound(net_id=id)
            if net.ports:
                raise exceptions.NetworkInUse(net_id=id)
            self.nvp_driver.delete_network(context.tenant_id, id)
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
        new_port = {'id': self._gen_uuid()}
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
        new_port = {'id': id}
        return self._make_port_dict(new_port)

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
        port = context.session.query(models.Port).\
                    filter(models.Port.id == id).\
                    first()
        if not port:
            raise exceptions.PortNotFound(port_id=id, net_id='')
        return self._make_port_dict(port)

    def _ports_query(self, context, filters, query=None):
        query = query or context.session.query(models.Port)
        if filters.get("network_id"):
            query = query.filter(
                    models.Port.network_id == filters["network_id"])

        if filters.get("device_id"):
            query = query.filter(models.Port.device_id == filters["device_id"])

        if filters.get("mac_address"):
            query = query.filter(
                    models.Port.mac_address == filters["mac_address"])

        if filters.get("tenant_id"):
            query = query.filter(
                    models.Port.tenant_id == filters["tenant_id"])
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
        #TODO(mdietz): May need to build a list of fields to query for later
        return [self._make_port_dict(p)
                for p in self._ports_query(context, filters).all()]

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
        query = context.session.query(sql_func.count(models.Port))
        return self._ports_query(context, filters, query=query).scalar()

    def delete_port(self, context, id):
        """
        Delete a port.
        : param context: quantum api request context
        : param id: UUID representing the port to delete.
        """
        pass
