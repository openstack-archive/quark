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
Ironic agent driver for Quark.
"""
import json
import netaddr

from neutron_lib import exceptions as n_exc
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from quark.drivers import base
from quark import network_strategy
from quark import utils

STRATEGY = network_strategy.STRATEGY

LOG = logging.getLogger(__name__)

CONF = cfg.CONF

IRONIC_IPAM_STRATEGIES = {
    "provider": {
        "default": "IRONIC_ANY",
        "overrides": {
            "BOTH_REQUIRED": "IRONIC_BOTH_REQUIRED",
            "BOTH": "IRONIC_BOTH",
            "ANY": "IRONIC_ANY"
        }
    },
    "tenant": {
        "overrides": {}
    }
}

ironic_opts = [
    # client connection info
    cfg.StrOpt("ironic_client", default="neutronclient.v2_0.client.Client",
               help=("Class of the client used to communicate with the "
                     "Ironic agent")),
    cfg.StrOpt('endpoint_url',
               default='http://127.0.0.1:9697',
               help='URL for connecting to neutron'),
    cfg.IntOpt('timeout',
               default=30,
               help='Timeout value for connecting to neutron in seconds.'),
    cfg.BoolOpt('insecure',
                default=False,
                help='If set, ignore any SSL validation issues'),
    cfg.StrOpt('ca_cert',
               help=('Location of CA certificates file to use for '
                     'neutron client requests.')),
    cfg.StrOpt('password',
               help='Password for connecting to neutron.', secret=True),
    cfg.StrOpt('tenant_name',
               help='Tenant name for connecting to neutron.'),
    cfg.StrOpt('tenant_id',
               help='Tenant id for connecting to neutron.'),
    cfg.StrOpt('auth_url',
               default='http://localhost:5000/v2.0',
               help='Authorization URL for connecting to neutron.'),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               help='Authorization strategy for connecting to neutron.'),

    # client retry options
    cfg.IntOpt("operation_retries",
               default=3,
               help="Number of times to attempt client operations."),
    cfg.IntOpt("operation_delay",
               default=0,
               help="Base seconds to wait between client attempts."),
    cfg.IntOpt("operation_backoff",
               default=0,
               help="Base seconds for client exponential backoff"),

    # conf options
    cfg.StrOpt("ironic_ipam_strategies",
               default=json.dumps(IRONIC_IPAM_STRATEGIES),
               help="Default IPAM strategies and overrides for this driver")
]

CONF.register_opts(ironic_opts, "IRONIC")


class FakeIronicClient(object):
    def __init__(self, *args, **kwargs):
        pass

    def create_port(self, *args, **kwargs):
        return {"port": {"vlan_id": 500, "id": "fake_uuid"}}

    def delete_port(self, *args, **kwargs):
        return


class IronicException(n_exc.NeutronException):
    message = "ironic driver error: %(msg)s"


class IronicDriver(base.BaseDriver):
    def __init__(self):
        self._client = None
        self._ipam_strategies = None
        super(IronicDriver, self).__init__()

    @classmethod
    def get_name(cls):
        return "IRONIC"

    def load_config(self):
        LOG.info("Loading Ironic settings.")
        self._client_cls = importutils.import_class(CONF.IRONIC.ironic_client)
        self._client = self._get_client()
        self._ipam_strategies = self._parse_ironic_ipam_strategies()
        LOG.info("Ironic Driver config loaded. Client: %s"
                 % (CONF.IRONIC.endpoint_url))

    def _get_client(self):

        params = {
            'endpoint_url': CONF.IRONIC.endpoint_url,
            'timeout': CONF.IRONIC.timeout,
            'insecure': CONF.IRONIC.insecure,
            'ca_cert': CONF.IRONIC.ca_cert,
            'auth_strategy': CONF.IRONIC.auth_strategy,
            'tenant_name': CONF.IRONIC.tenant_name,
            'tenant_id': CONF.IRONIC.tenant_id,
            'password': CONF.IRONIC.password
        }
        return self._client_cls(**params)

    def _parse_ironic_ipam_strategies(self):
        strategies = json.loads(CONF.IRONIC.ironic_ipam_strategies)

        for net_type in ['provider', 'tenant']:

            strategy = strategies.get(net_type, {})
            default = strategy.get("default")

            # provider nets must specify a default IPAM strategy
            if net_type == 'provider':
                if not default:
                    raise Exception("ironic_ipam_strategies must have a "
                                    "default 'provider' strategy.")

        return strategies

    def select_ipam_strategy(self, network_id, network_strategy, **kwargs):
        """Return relevant IPAM strategy name.

        :param network_id: neutron network id.
        :param network_strategy: default strategy for the network.

        NOTE(morgabra) This feels like a hack but I can't think of a better
        idea. The root problem is we can now attach ports to networks with
        a different backend driver/ipam strategy than the network speficies.

        We handle the the backend driver part with allowing network_plugin to
        be specified for port objects. This works pretty well because nova or
        whatever knows when we are hooking up an Ironic node so it can pass
        along that key during port_create().

        IPAM is a little trickier, especially in Ironic's case, because we
        *must* use a specific IPAM for provider networks. There isn't really
        much of an option other than involve the backend driver when selecting
        the IPAM strategy.
        """
        LOG.info("Selecting IPAM strategy for network_id:%s "
                 "network_strategy:%s" % (network_id, network_strategy))

        net_type = "tenant"
        if STRATEGY.is_provider_network(network_id):
            net_type = "provider"

        strategy = self._ipam_strategies.get(net_type, {})
        default = strategy.get("default")
        overrides = strategy.get("overrides", {})

        # If we override a particular strategy explicitly, we use it.
        if network_strategy in overrides:
            LOG.info("Selected overridden IPAM strategy: %s"
                     % (overrides[network_strategy]))
            return overrides[network_strategy]

        # Otherwise, we are free to use an explicit default.
        if default:
            LOG.info("Selected default IPAM strategy for tenant "
                     "network: %s" % (default))
            return default

        # Fallback to the network-specified IPAM strategy
        LOG.info("Selected network strategy for tenant "
                 "network: %s" % (network_strategy))
        return network_strategy

    def _make_subnet_dict(self, subnet):

        dns_nameservers = [str(netaddr.IPAddress(dns["ip"]))
                           for dns in subnet.get("dns_nameservers")]

        host_routes = [{"destination": r["cidr"],
                        "nexthop": r["gateway"]} for r in subnet["routes"]]

        res = {
            "id": subnet.get("id"),
            "name": subnet.get("name"),
            "tenant_id": subnet.get("tenant_id"),
            "dns_nameservers": dns_nameservers,
            "host_routes": host_routes,
            "cidr": subnet.get("cidr"),
            "gateway_ip": subnet.get("gateway_ip")
        }

        return res

    def _make_fixed_ip_dict(self, context, address):
        return {"subnet": self._make_subnet_dict(address["subnet"]),
                "ip_address": address["address_readable"]}

    @utils.retry_loop(CONF.IRONIC.operation_retries,
                      delay=CONF.IRONIC.operation_delay,
                      backoff=CONF.IRONIC.operation_backoff)
    def _create_port(self, context, body):
        try:
            return self._client.create_port(body={"port": body})
        except Exception as e:
            msg = "failed to create downstream port. Exception: %s" % (str(e))
            LOG.exception(msg)
            raise

    def _get_base_network_info(self, context, network_id, base_net_driver):
        """Return a dict of extra network information.

        :param context: neutron request context.
        :param network_id: neturon network id.
        :param net_driver: network driver associated with network_id.
        :raises IronicException: Any unexpected data fetching failures will
            be logged and IronicException raised.

        This driver can attach to networks managed by other drivers. We may
        need some information from these drivers, or otherwise inform
        downstream about the type of network we are attaching to. We can
        make these decisions here.
        """
        driver_name = base_net_driver.get_name()
        net_info = {"network_type": driver_name}
        LOG.debug('_get_base_network_info: %s %s'
                  % (driver_name, network_id))

        # If the driver is NVP, we need to look up the lswitch id we should
        # be attaching to.
        if driver_name == 'NVP':
            LOG.debug('looking up lswitch ids for network %s'
                      % (network_id))
            lswitch_ids = base_net_driver.get_lswitch_ids_for_network(
                context, network_id)

            if not lswitch_ids or len(lswitch_ids) > 1:
                msg = ('lswitch id lookup failed, %s ids found.'
                       % (len(lswitch_ids)))
                LOG.error(msg)
                raise IronicException(msg)

            lswitch_id = lswitch_ids.pop()
            LOG.info('found lswitch for network %s: %s'
                     % (network_id, lswitch_id))
            net_info['lswitch_id'] = lswitch_id

        LOG.debug('_get_base_network_info finished: %s %s %s'
                  % (driver_name, network_id, net_info))
        return net_info

    def create_port(self, context, network_id, port_id, **kwargs):
        """Create a port.

        :param context: neutron api request context.
        :param network_id: neutron network id.
        :param port_id: neutron port id.
        :param kwargs:
            required keys - device_id: neutron port device_id (instance_id)
                            instance_node_id: nova hypervisor host id
                            mac_address: neutron port mac address
                            base_net_driver: the base network driver
            optional keys - addresses: list of allocated IPAddress models
                            security_groups: list of associated security groups
        :raises IronicException: If the client is unable to create the
            downstream port for any reason, the exception will be logged
            and IronicException raised.
        """
        LOG.info("create_port %s %s %s" % (context.tenant_id, network_id,
                                           port_id))

        # sanity check
        if not kwargs.get('base_net_driver'):
            raise IronicException(msg='base_net_driver required.')
        base_net_driver = kwargs['base_net_driver']

        if not kwargs.get('device_id'):
            raise IronicException(msg='device_id required.')
        device_id = kwargs['device_id']

        if not kwargs.get('instance_node_id'):
            raise IronicException(msg='instance_node_id required.')
        instance_node_id = kwargs['instance_node_id']

        if not kwargs.get('mac_address'):
            raise IronicException(msg='mac_address is required.')
        mac_address = str(netaddr.EUI(kwargs["mac_address"]["address"]))
        mac_address = mac_address.replace('-', ':')

        # TODO(morgabra): Change this when we enable security groups.
        if kwargs.get('security_groups'):
            msg = 'ironic driver does not support security group operations.'
            raise IronicException(msg=msg)

        # unroll the given address models into a fixed_ips list we can
        # pass downstream
        fixed_ips = []
        addresses = kwargs.get('addresses')
        if not isinstance(addresses, list):
            addresses = [addresses]
        for address in addresses:
            fixed_ips.append(self._make_fixed_ip_dict(context, address))

        body = {
            "id": port_id,
            "network_id": network_id,
            "device_id": device_id,
            "device_owner": kwargs.get('device_owner', ''),
            "tenant_id": context.tenant_id or "quark",
            "roles": context.roles,
            "mac_address": mac_address,
            "fixed_ips": fixed_ips,
            "switch:hardware_id": instance_node_id,
            "dynamic_network": not STRATEGY.is_provider_network(network_id)
        }

        net_info = self._get_base_network_info(
            context, network_id, base_net_driver)
        body.update(net_info)

        try:
            LOG.info("creating downstream port: %s" % (body))
            port = self._create_port(context, body)
            LOG.info("created downstream port: %s" % (port))
            return {"uuid": port['port']['id'],
                    "vlan_id": port['port']['vlan_id']}
        except Exception as e:
            msg = "failed to create downstream port. Exception: %s" % (e)
            raise IronicException(msg=msg)

    def update_port(self, context, port_id, **kwargs):
        """Update a port.

        :param context: neutron api request context.
        :param port_id: neutron port id.
        :param kwargs: optional kwargs.
        :raises IronicException: If the client is unable to update the
            downstream port for any reason, the exception will be logged
            and IronicException raised.

        TODO(morgabra) It does not really make sense in the context of Ironic
        to allow updating ports. fixed_ips and mac_address are burned in the
        configdrive on the host, and we otherwise cannot migrate a port between
        instances. Eventually we will need to support security groups, but for
        now it's a no-op on port data changes, and we need to rely on the
        API/Nova to not allow updating data on active ports.
        """
        LOG.info("update_port %s %s" % (context.tenant_id, port_id))

        # TODO(morgabra): Change this when we enable security groups.
        if kwargs.get("security_groups"):
            msg = 'ironic driver does not support security group operations.'
            raise IronicException(msg=msg)

        return {"uuid": port_id}

    @utils.retry_loop(CONF.IRONIC.operation_retries,
                      delay=CONF.IRONIC.operation_delay,
                      backoff=CONF.IRONIC.operation_backoff)
    def _delete_port(self, context, port_id):
        try:
            return self._client.delete_port(port_id)
        except Exception as e:
            # This doesn't get wrapped by the client unfortunately.
            if "404 not found" in str(e).lower():
                LOG.error("port %s not found downstream. ignoring delete."
                          % (port_id))
                return

            msg = ("failed to delete downstream port. "
                   "exception: %s" % (e))
            LOG.exception(msg)
            raise

    def delete_port(self, context, port_id, **kwargs):
        """Delete a port.

        :param context: neutron api request context.
        :param port_id: neutron port id.
        :param kwargs: optional kwargs.
        :raises IronicException: If the client is unable to delete the
            downstream port for any reason, the exception will be logged
            and IronicException raised.
        """
        LOG.info("delete_port %s %s" % (context.tenant_id, port_id))
        try:
            self._delete_port(context, port_id)
            LOG.info("deleted downstream port: %s" % (port_id))
        except Exception:
            LOG.error("failed deleting downstream port, it is now "
                      "orphaned! port_id: %s" % (port_id))

    def diag_port(self, context, port_id, **kwargs):
        """Diagnose a port.

        :param context: neutron api request context.
        :param port_id: neutron port id.
        :param kwargs: optional kwargs.
        :raises IronicException: If the client is unable to fetch the
            downstream port for any reason, the exception will be
            logged and IronicException raised.
        """
        LOG.info("diag_port %s" % port_id)
        try:
            port = self._client.show_port(port_id)
        except Exception as e:
            msg = "failed fetching downstream port: %s" % (str(e))
            LOG.exception(msg)
            raise IronicException(msg=msg)
        return {"downstream_port": port}

    def create_network(self, *args, **kwargs):
        """Create a network.

        :raises NotImplementedError: This driver does not manage networks.

        NOTE: This is a no-op in the base driver, but this raises here as to
        explicitly disallow network operations in case of a misconfiguration.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'network operations.')

    def delete_network(self, *args, **kwargs):
        """Delete a network.

        :raises NotImplementedError: This driver does not manage networks.

        NOTE: This is a no-op in the base driver, but this raises here as to
        explicitly disallow network operations in case of a misconfiguration.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'network operations.')

    def diag_network(self, *args, **kwargs):
        """Diagnose a network.

        :raises NotImplementedError: This driver does not manage networks.

        NOTE: This is a no-op in the base driver, but this raises here as to
        explicitly disallow network operations in case of a misconfiguration.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'network operations.')

    def create_security_group(self, context, group_name, **group):
        """Create a security group.

        :raises NotImplementedError: This driver does not implement security
                                     groups.

        NOTE: Security groups will be supported in the future, but for now
        they are explicitly disallowed.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'security group operations.')

    def delete_security_group(self, context, group_id, **kwargs):
        """Delete a security group.

        :raises NotImplementedError: This driver does not implement security
                                     groups.

        NOTE: Security groups will be supported in the future, but for now
        they are explicitly disallowed.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'security group operations.')

    def update_security_group(self, context, group_id, **group):
        """Update a security group.

        :raises NotImplementedError: This driver does not implement security
                                     groups.

        NOTE: Security groups will be supported in the future, but for now
        they are explicitly disallowed.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'security group operations.')

    def create_security_group_rule(self, context, group_id, rule):
        """Create a security group rule.

        :raises NotImplementedError: This driver does not implement security
                                     groups.

        NOTE: Security groups will be supported in the future, but for now
        they are explicitly disallowed.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'security group operations.')

    def delete_security_group_rule(self, context, group_id, rule):
        """Delete a security group rule.

        :raises NotImplementedError: This driver does not implement security
                                     groups.

        NOTE: Security groups will be supported in the future, but for now
        they are explicitly disallowed.
        """
        raise NotImplementedError('ironic driver does not support '
                                  'security group operations.')
