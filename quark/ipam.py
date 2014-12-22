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
Quark Pluggable IPAM
"""

import functools
import itertools
import random
import uuid

import netaddr
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.openstack.common import lockutils
from neutron.openstack.common import log as logging
from oslo.config import cfg
from oslo.db import exception as db_exception
from oslo.utils import timeutils

from quark.db import api as db_api
from quark.db import ip_types
from quark.db import models
from quark import exceptions as q_exc
from quark import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF

quark_opts = [
    cfg.IntOpt('v6_allocation_attempts',
               default=10,
               help=_('Number of times to retry generating v6 addresses'
                      ' before failure. Also implicitly controls how many'
                      ' v6 addresses we assign to any port, as the random'
                      ' values generated will be the same every time.')),
    cfg.IntOpt("mac_address_retry_max",
               default=20,
               help=_("Number of times to attempt to allocate a new MAC"
                      " address before giving up.")),
    cfg.IntOpt("ip_address_retry_max",
               default=20,
               help=_("Number of times to attempt to allocate a new IP"
                      " address before giving up.")),
    cfg.BoolOpt("ipam_use_synchronization",
                default=False,
                help=_("Configures whether or not to use the experimental"
                       " semaphore logic around IPAM"))
]

CONF.register_opts(quark_opts, "QUARK")

# NOTE(mdietz): equivalent to the following line, but converting
#               v6 addresses in netaddr is very slow.
# netaddr.IPAddress("::0200:0:0:0").value
MAGIC_INT = 144115188075855872


def no_synchronization(*args, **kwargs):
    def wrap(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            return f(*args, **kwargs)
        return inner
    return wrap


def named(sema):
    return "%s.%s" % (__name__, sema)


if CONF.QUARK.ipam_use_synchronization:
    synchronized = lockutils.synchronized
else:
    synchronized = no_synchronization


def rfc2462_ip(mac, cidr):
    # NOTE(mdietz): see RFC2462
    int_val = netaddr.IPNetwork(cidr).value
    mac = netaddr.EUI(mac)
    int_val += mac.eui64().value
    int_val ^= MAGIC_INT
    return int_val


def rfc3041_ip(port_id, cidr):
    random.seed(int(uuid.UUID(port_id)))
    int_val = netaddr.IPNetwork(cidr).value
    while True:
        val = int_val + random.getrandbits(64)
        val ^= MAGIC_INT
        yield val


def generate_v6(mac, port_id, cidr):
    yield rfc2462_ip(mac, cidr)
    for addr in rfc3041_ip(port_id, cidr):
        yield addr


class QuarkIpam(object):
    @synchronized(named("allocate_mac_address"))
    def allocate_mac_address(self, context, net_id, port_id, reuse_after,
                             mac_address=None):
        if mac_address:
            mac_address = netaddr.EUI(mac_address).value

        kwargs = {"network_id": net_id, "port_id": port_id,
                  "mac_address": mac_address}
        LOG.info(("Attempting to allocate a new MAC address "
                  "[{0}]").format(utils.pretty_kwargs(**kwargs)))

        for retry in xrange(CONF.QUARK.mac_address_retry_max):
            LOG.info("Attemping to reallocate deallocated MAC (step 1 of 3),"
                     " attempt {0} of {1}".format(
                         retry + 1, CONF.QUARK.mac_address_retry_max))
            try:
                with context.session.begin():
                    deallocated_mac = db_api.mac_address_find(
                        context, lock_mode=True, reuse_after=reuse_after,
                        deallocated=True, scope=db_api.ONE,
                        address=mac_address, order_by="address ASC")

                    if deallocated_mac:
                        dealloc = netaddr.EUI(deallocated_mac["address"])
                        LOG.info("Found a suitable deallocated MAC {0}".format(
                            str(dealloc)))

                        address = db_api.mac_address_update(
                            context, deallocated_mac, deallocated=False,
                            deallocated_at=None)

                        LOG.info("MAC assignment for port ID {0} completed "
                                 "with address {1}".format(port_id, dealloc))
                        return address
                    break
            except Exception:
                LOG.exception("Error in mac reallocate...")
                continue

        LOG.info("Couldn't find a suitable deallocated MAC, attempting "
                 "to create a new one")

        # This could fail if a large chunk of MACs were chosen explicitly,
        # but under concurrent load enough MAC creates should iterate without
        # any given thread exhausting its retry count.
        for retry in xrange(CONF.QUARK.mac_address_retry_max):
            LOG.info("Attemping to find a range to create a new MAC in "
                     "(step 2 of 3), attempt {0} of {1}".format(
                         retry + 1, CONF.QUARK.mac_address_retry_max))
            next_address = None
            with context.session.begin():
                try:
                    fn = db_api.mac_address_range_find_allocation_counts
                    mac_range = fn(context, address=mac_address)

                    if not mac_range:
                        LOG.info("No MAC ranges could be found given "
                                 "the criteria")
                        break

                    rng, addr_count = mac_range
                    LOG.info("Found a MAC range {0}".format(rng["cidr"]))

                    last = rng["last_address"]
                    first = rng["first_address"]
                    if (last - first + 1) <= addr_count:
                        # Somehow, the range got filled up without us
                        # knowing, so set the next_auto_assign to be -1
                        # so we never try to create new ones
                        # in this range
                        rng["next_auto_assign_mac"] = -1
                        context.session.add(rng)
                        LOG.info("MAC range {0} is full".format(rng["cidr"]))
                        continue

                    if mac_address:
                        next_address = mac_address
                    else:
                        next_address = rng["next_auto_assign_mac"]
                        next_auto = next_address + 1
                        if next_auto > last:
                            next_auto = -1
                        db_api.mac_address_range_update(
                            context, rng, next_auto_assign_mac=next_auto)

                except Exception:
                    LOG.exception("Error in updating mac range")
                    continue

            # Based on the above, this should only fail if a MAC was
            # was explicitly chosen at some point. As such, fall through
            # here and get in line for a new MAC address to try
            try:
                mac_readable = str(netaddr.EUI(next_address))
                LOG.info("Attempting to create new MAC {0} "
                         "(step 3 of 3)".format(mac_readable))
                with context.session.begin():
                    address = db_api.mac_address_create(
                        context, address=next_address,
                        mac_address_range_id=rng["id"])
                    LOG.info("MAC assignment for port ID {0} completed with "
                             "address {1}".format(port_id, mac_readable))
                    return address
            except Exception:
                LOG.info("Failed to create new MAC {0}".format(mac_readable))
                LOG.exception("Error in creating mac. MAC possibly duplicate")
                continue

        raise exceptions.MacAddressGenerationFailure(net_id=net_id)

    @synchronized(named("reallocate_ip"))
    def attempt_to_reallocate_ip(self, context, net_id, port_id, reuse_after,
                                 version=None, ip_address=None,
                                 segment_id=None, subnets=None, **kwargs):
        version = version or [4, 6]
        elevated = context.elevated()

        LOG.info("Attempting to reallocate an IP (step 1 of 3) - [{0}]".format(
            utils.pretty_kwargs(network_id=net_id, port_id=port_id,
                                version=version, segment_id=segment_id,
                                subnets=subnets)))

        if version == 6 and "mac_address" in kwargs and kwargs["mac_address"]:
            # Defers to the create case. The reason why is we'd have to look
            # up subnets here to correctly generate the v6. If we split them
            # up into reallocate and create, we'd be looking up the same
            # subnets twice, which is a waste of time.

            # TODO(mdietz): after reviewing this code, this block annoyingly
            #               doesn't trigger in the ANY case, since we end up
            #               using a list of [4, 6]. It works as expected most
            #               of the time, but we can anticipate that isolated
            #               networks will end up using sequential assignment.
            #               Probably want to rework this logic to compensate
            #               at some point. Considering they all come from the
            #               same MAC address pool, nothing bad will happen,
            #               just worth noticing and fixing.
            LOG.info("Identified as v6 case, deferring to IP create path")
            return []

        sub_ids = []
        if subnets:
            sub_ids = subnets
        else:
            if segment_id:
                subnets = db_api.subnet_find(elevated,
                                             network_id=net_id,
                                             segment_id=segment_id)
                sub_ids = [s["id"] for s in subnets]
                if not sub_ids:
                    LOG.info("No subnets matching segment_id {0} could be "
                             "found".format(segment_id))
                    raise exceptions.IpAddressGenerationFailure(
                        net_id=net_id)

        ip_kwargs = {
            "network_id": net_id, "reuse_after": reuse_after,
            "deallocated": True, "scope": db_api.ONE,
            "ip_address": ip_address, "lock_mode": True,
            "version": version, "order_by": "address"}

        if sub_ids:
            ip_kwargs["subnet_id"] = sub_ids

        # We never want to take the chance of an infinite loop here. Instead,
        # we'll clean up multiple bad IPs if we find them (assuming something
        # is really wrong)
        for retry in xrange(CONF.QUARK.ip_address_retry_max):
            LOG.info("Attempt {0} of {1}".format(
                retry + 1, CONF.QUARK.ip_address_retry_max))
            get_policy = models.IPPolicy.get_ip_policy_cidrs

            try:
                with context.session.begin():
                    # NOTE(mdietz): Before I removed the lazy=joined, this
                    #               raised with an unknown column "address"
                    #               error.
                    address = db_api.ip_address_find(elevated, **ip_kwargs)

                    if address:
                        # NOTE(mdietz): We should always be in the CIDR but we
                        #              also said that before :-/
                        LOG.info("Potentially reallocatable IP found: "
                                 "{0}".format(address["address_readable"]))
                        subnet = address.get('subnet')
                        if subnet:
                            if subnet["do_not_use"]:
                                continue

                            policy = get_policy(subnet)

                            cidr = netaddr.IPNetwork(address["subnet"]["cidr"])
                            addr = netaddr.IPAddress(int(address["address"]))
                            if address["subnet"]["ip_version"] == 4:
                                addr = addr.ipv4()
                            else:
                                addr = addr.ipv6()

                            if policy is not None and addr in policy:
                                LOG.info("Deleting Address {0} due to policy "
                                         "violation".format(
                                             address["address_readable"]))

                                context.session.delete(address)
                                continue
                            if addr in cidr:
                                LOG.info("Marking Address {0} as "
                                         "allocated".format(
                                             address["address_readable"]))
                                updated_address = db_api.ip_address_update(
                                    elevated, address, deallocated=False,
                                    deallocated_at=None,
                                    used_by_tenant_id=context.tenant_id,
                                    allocated_at=timeutils.utcnow(),
                                    port_id=port_id,
                                    address_type=kwargs.get('address_type',
                                                            ip_types.FIXED))
                                return [updated_address]
                            else:
                                # Make sure we never find it again
                                LOG.info("Address {0} isn't in the subnet "
                                         "it claims to be in".format(
                                             address["address_readable"]))
                                context.session.delete(address)
                    else:
                        LOG.info("Couldn't find any reallocatable addresses "
                                 "given the criteria")
                        break
            except Exception:
                LOG.exception("Error in reallocate ip...")
        return []

    def is_strategy_satisfied(self, ip_addresses, allocate_complete=False):
        return ip_addresses

    def _allocate_from_subnet(self, context, net_id, subnet,
                              port_id, reuse_after, ip_address=None, **kwargs):

        LOG.info("Creating a new address in subnet {0} - [{1}]".format(
            subnet["_cidr"], utils.pretty_kwargs(network_id=net_id,
                                                 subnet=subnet,
                                                 port_id=port_id,
                                                 ip_address=ip_address)))

        ip_policy_cidrs = models.IPPolicy.get_ip_policy_cidrs(subnet)
        next_ip = ip_address
        if not next_ip:
            if subnet["next_auto_assign_ip"] != -1:
                next_ip = netaddr.IPAddress(subnet["next_auto_assign_ip"] - 1)
            else:
                next_ip = netaddr.IPAddress(subnet["last_ip"])
            if subnet["ip_version"] == 4:
                next_ip = next_ip.ipv4()

        LOG.info("Next IP is {0}".format(str(next_ip)))
        if ip_policy_cidrs and next_ip in ip_policy_cidrs and not ip_address:
            LOG.info("Next IP {0} violates policy".format(str(next_ip)))
            raise q_exc.IPAddressPolicyRetryableFailure(ip_addr=next_ip,
                                                        net_id=net_id)
        try:
            with context.session.begin():
                address = db_api.ip_address_create(
                    context, address=next_ip, subnet_id=subnet["id"],
                    deallocated=0, version=subnet["ip_version"],
                    network_id=net_id,
                    port_id=port_id,
                    address_type=kwargs.get('address_type', ip_types.FIXED))
                address["deallocated"] = 0
        except Exception:
            # NOTE(mdietz): Our version of sqlalchemy incorrectly raises None
            #               here when there's an IP conflict
            if ip_address:
                raise exceptions.IpAddressInUse(ip_address=next_ip,
                                                net_id=net_id)
            raise q_exc.IPAddressRetryableFailure(ip_addr=next_ip,
                                                  net_id=net_id)

        return address

    def _allocate_from_v6_subnet(self, context, net_id, subnet,
                                 port_id, reuse_after, ip_address=None,
                                 **kwargs):
        """This attempts to allocate v6 addresses as per RFC2462 and RFC3041.

        To accomodate this, we effectively treat all v6 assignment as a
        first time allocation utilizing the MAC address of the VIF. Because
        we recycle MACs, we will eventually attempt to recreate a previously
        generated v6 address. Instead of failing, we've opted to handle
        reallocating that address in this method.

        This should provide a performance boost over attempting to check
        each and every subnet in the existing reallocate logic, as we'd
        have to iterate over each and every subnet returned
        """

        LOG.info("Attempting to allocate a v6 address - [{0}]".format(
            utils.pretty_kwargs(network_id=net_id, subnet=subnet,
                                port_id=port_id, ip_address=ip_address)))

        if (ip_address or "mac_address" not in kwargs or
                not kwargs["mac_address"]):
            LOG.info("No MAC addressed supplied, defaulting to sequential "
                     "allocation")
            return self._allocate_from_subnet(context, net_id=net_id,
                                              subnet=subnet, port_id=port_id,
                                              reuse_after=reuse_after,
                                              ip_address=ip_address, **kwargs)
        else:
            ip_policy_cidrs = models.IPPolicy.get_ip_policy_cidrs(subnet)
            for tries, ip_address in enumerate(
                generate_v6(kwargs["mac_address"]["address"], port_id,
                            subnet["cidr"])):

                LOG.info("Attempt {0} of {1}".format(
                    tries + 1, CONF.QUARK.v6_allocation_attempts))

                if tries > CONF.QUARK.v6_allocation_attempts - 1:
                    LOG.info("Exceeded v6 allocation attempts, bailing")
                    raise exceptions.IpAddressGenerationFailure(
                        net_id=net_id)

                ip_address = netaddr.IPAddress(ip_address).ipv6()
                LOG.info("Generated a new v6 address {0}".format(
                    str(ip_address)))

                # NOTE(mdietz): treating the IPSet as a boolean caused netaddr
                #               to attempt to enumerate the entire set!
                if (ip_policy_cidrs is not None and
                        ip_address in ip_policy_cidrs):
                    LOG.info("Address {0} excluded by policy".format(
                        str(ip_address)))
                    continue

                # TODO(mdietz): replace this with a compare-and-swap loop
                with context.session.begin():
                    address = db_api.ip_address_find(
                        context, network_id=net_id, ip_address=ip_address,
                        scope=db_api.ONE, reuse_after=reuse_after,
                        deallocated=True, subnet_id=subnet["id"],
                        lock_mode=True)

                    if address:
                        LOG.info("Address {0} exists, claiming".format(
                            str(ip_address)))
                        return db_api.ip_address_update(
                            context, address, deallocated=False,
                            deallocated_at=None,
                            used_by_tenant_id=context.tenant_id,
                            allocated_at=timeutils.utcnow(),
                            address_type=kwargs.get('address_type',
                                                    ip_types.FIXED))

                # This triggers when the IP is allocated to another tenant,
                # either because we missed it due to our filters above, or
                # in an extremely unlikely race between the find and here.
                try:
                    with context.session.begin():
                        return db_api.ip_address_create(
                            context, address=ip_address,
                            subnet_id=subnet["id"],
                            version=subnet["ip_version"], network_id=net_id,
                            address_type=kwargs.get('address_type',
                                                    ip_types.FIXED))
                except db_exception.DBDuplicateEntry:
                    LOG.info("{0} exists but was already "
                             "allocated".format(str(ip_address)))
                    LOG.debug("Duplicate entry found when inserting subnet_id"
                              " %s ip_address %s", subnet["id"], ip_address)

    def _allocate_ips_from_subnets(self, context, new_addresses, net_id,
                                   subnets, port_id, reuse_after,
                                   ip_address=None, **kwargs):

        LOG.info("Allocating IP(s) from chosen subnet(s) (step 3 of 3) - "
                 "[{0}]".format(utils.pretty_kwargs(
                     network_id=net_id, port_id=port_id,
                     new_addresses=new_addresses, ip_address=ip_address)))

        subnets = subnets or []
        for subnet in subnets:
            if not subnet:
                continue

            LOG.info("Attempting to allocate from {0} - {1}".format(
                subnet["id"], subnet["_cidr"]))

            address = None
            if int(subnet["ip_version"]) == 4:
                address = self._allocate_from_subnet(context, net_id,
                                                     subnet, port_id,
                                                     reuse_after,
                                                     ip_address, **kwargs)
            else:
                address = self._allocate_from_v6_subnet(context, net_id,
                                                        subnet, port_id,
                                                        reuse_after,
                                                        ip_address, **kwargs)
            if address:
                LOG.info("Created IP {0}".format(
                    address["address_readable"]))
                new_addresses.append(address)

        return new_addresses

    def _notify_new_addresses(self, context, new_addresses):
        for addr in new_addresses:
            payload = dict(used_by_tenant_id=addr["used_by_tenant_id"],
                           ip_block_id=addr["subnet_id"],
                           ip_address=addr["address_readable"],
                           device_ids=[p["device_id"] for p in addr["ports"]],
                           created_at=addr["created_at"])
            n_rpc.get_notifier("network").info(context,
                                               "ip_block.address.create",
                                               payload)

    def allocate_ip_address(self, context, new_addresses, net_id, port_id,
                            reuse_after, segment_id=None, version=None,
                            ip_addresses=None, subnets=None, **kwargs):
        elevated = context.elevated()
        subnets = subnets or []
        ip_addresses = ip_addresses or []

        LOG.info("Starting a new IP address(es) allocation. Strategy "
                 "is {0} - [{1}]".format(
                     self.get_name(),
                     utils.pretty_kwargs(network_id=net_id, port_id=port_id,
                                         new_addresses=new_addresses,
                                         ip_addresses=ip_addresses,
                                         subnets=subnets,
                                         segment_id=segment_id,
                                         version=version)))

        def _try_reallocate_ip_address(ip_addr=None):
            new_addresses.extend(self.attempt_to_reallocate_ip(
                context, net_id, port_id, reuse_after, version=None,
                ip_address=ip_addr, segment_id=segment_id, subnets=subnets,
                **kwargs))

        def _try_allocate_ip_address(ip_addr=None, sub=None):
            for retry in xrange(CONF.QUARK.ip_address_retry_max):
                LOG.info("Allocating new IP attempt {0} of {1}".format(
                    retry + 1, CONF.QUARK.ip_address_retry_max))
                if not sub:
                    subnets = self._choose_available_subnet(
                        elevated, net_id, version, segment_id=segment_id,
                        ip_address=ip_addr, reallocated_ips=new_addresses)
                else:
                    subnets = [self.select_subnet(context, net_id,
                                                  ip_addr, segment_id,
                                                  subnet_ids=[sub])]

                LOG.info("Subnet selection returned {0} viable subnet(s) - "
                         "IDs: {1}".format(len(subnets),
                                           ", ".join([str(s["id"])
                                                      for s in subnets if s])))

                try:
                    self._allocate_ips_from_subnets(context, new_addresses,
                                                    net_id, subnets,
                                                    port_id, reuse_after,
                                                    ip_addr, **kwargs)
                except q_exc.IPAddressRetryableFailure:
                    LOG.exception("Error in allocating IP")
                    remaining = CONF.QUARK.ip_address_retry_max - retry - 1
                    if remaining > 0:
                        LOG.info("{0} retries remain, retrying...".format(
                            remaining))
                    else:
                        LOG.info("No retries remaing, bailing")
                    continue

                break

        ip_addresses = [netaddr.IPAddress(ip_address)
                        for ip_address in ip_addresses]

        if ip_addresses:
            for ip_address in ip_addresses:
                _try_reallocate_ip_address(ip_address)
        else:
            _try_reallocate_ip_address()

        if self.is_strategy_satisfied(new_addresses):
            return
        else:
            LOG.info("Reallocated addresses {0} but still need more addresses "
                     "to satisfy strategy {1}. Falling back to creating "
                     "IPs".format(new_addresses, self.get_name()))

        if ip_addresses or subnets:
            for ip_address, subnet in itertools.izip_longest(ip_addresses,
                                                             subnets):
                _try_allocate_ip_address(ip_address, subnet)
        else:
            _try_allocate_ip_address()

        if self.is_strategy_satisfied(new_addresses, allocate_complete=True):
            self._notify_new_addresses(context, new_addresses)
            LOG.info("IPAM for port ID {0} completed with addresses "
                     "{1}".format(port_id,
                                  [a["address_readable"]
                                   for a in new_addresses]))
            return

        raise exceptions.IpAddressGenerationFailure(net_id=net_id)

    def deallocate_ip_address(self, context, address):
        address["deallocated"] = 1
        address["address_type"] = None
        payload = dict(used_by_tenant_id=address["used_by_tenant_id"],
                       ip_block_id=address["subnet_id"],
                       ip_address=address["address_readable"],
                       device_ids=[p["device_id"] for p in address["ports"]],
                       created_at=address["created_at"],
                       deleted_at=timeutils.utcnow())
        n_rpc.get_notifier("network").info(context,
                                           "ip_block.address.delete",
                                           payload)

    def deallocate_ips_by_port(self, context, port=None, **kwargs):
        ips_removed = []
        for addr in port["ip_addresses"]:
            if "ip_address" in kwargs:
                ip = kwargs["ip_address"]
                if ip != netaddr.IPAddress(int(addr["address"])):
                    continue

            # Note: only deallocate ip if this is the
            # only port mapped
            if len(addr["ports"]) == 1:
                self.deallocate_ip_address(context, addr)
            ips_removed.append(addr)

        port["ip_addresses"] = list(
            set(port["ip_addresses"]) - set(ips_removed))

    def deallocate_mac_address(self, context, address):
        mac = db_api.mac_address_find(context, address=address,
                                      scope=db_api.ONE)
        if not mac:
            raise exceptions.NotFound(
                message="No MAC address %s found" % netaddr.EUI(address))
        db_api.mac_address_update(context, mac, deallocated=True,
                                  deallocated_at=timeutils.utcnow())

    # RM6180(roaet):
    # - removed session.begin due to deadlocks
    # - fix off-by-one error and overflow
    @synchronized(named("select_subnet"))
    def select_subnet(self, context, net_id, ip_address, segment_id,
                      subnet_ids=None, **filters):
        LOG.info("Selecting subnet(s) - (Step 2 of 3) [{0}]".format(
            utils.pretty_kwargs(network_id=net_id, ip_address=ip_address,
                                segment_id=segment_id, subnet_ids=subnet_ids,
                                ip_version=filters.get("ip_version"))))

        with context.session.begin():
            subnets = db_api.subnet_find_ordered_by_most_full(
                context, net_id, segment_id=segment_id, scope=db_api.ALL,
                subnet_id=subnet_ids, **filters)

            if not subnets:
                LOG.info("No subnets found given the search criteria!")

            for subnet, ips_in_subnet in subnets:
                ipnet = netaddr.IPNetwork(subnet["cidr"])
                LOG.info("Trying subnet ID: {0} - CIDR: {1}".format(
                    subnet["id"], subnet["_cidr"]))
                if ip_address:
                    na_ip = netaddr.IPAddress(ip_address)
                    if ipnet.version == 4 and na_ip.version != 4:
                        na_ip = na_ip.ipv4()
                    if na_ip not in ipnet:
                        if subnet_ids is not None:
                            LOG.info("Requested IP {0} not in subnet {1}, "
                                     "retrying".format(str(na_ip), str(ipnet)))
                            raise q_exc.IPAddressNotInSubnet(
                                ip_addr=ip_address, subnet_id=subnet["id"])
                        continue

                ip_policy = None
                if not ip_address:
                    # Policies don't prevent explicit assignment, so we only
                    # need to check if we're allocating a new IP
                    ip_policy = subnet.get("ip_policy")

                policy_size = ip_policy["size"] if ip_policy else 0

                if ipnet.size > (ips_in_subnet + policy_size - 1):
                    if not ip_address:
                        ip = subnet["next_auto_assign_ip"]
                        # NOTE(mdietz): When atomically updated, this probably
                        #               doesn't need the lower bounds check but
                        #               I'm not comfortable removing it yet.
                        if ip < subnet["first_ip"] or ip > subnet["last_ip"]:
                            LOG.info("Marking subnet {0} as full".format(
                                subnet["id"]))
                            updated = db_api.subnet_update_set_full(context,
                                                                    subnet)
                        else:
                            updated = db_api.subnet_update_next_auto_assign_ip(
                                context, subnet)

                        if updated:
                            context.session.refresh(subnet)
                        else:
                            # This means the subnet was marked full while
                            # we were checking out policies. Fall out and
                            # go back to the outer retry loop.
                            return

                    LOG.info("Subnet {0} - {1} {2} looks viable, "
                             "returning".format(subnet["id"], subnet["_cidr"],
                                                subnet["next_auto_assign_ip"]))
                    return subnet
                else:
                    LOG.info("Marking subnet {0} as full".format(subnet["id"]))
                    db_api.subnet_update_set_full(context, subnet)


class QuarkIpamANY(QuarkIpam):
    @classmethod
    def get_name(self):
        return "ANY"

    def _choose_available_subnet(self, context, net_id, version=None,
                                 segment_id=None, ip_address=None,
                                 reallocated_ips=None):
        filters = {}
        if version:
            filters["ip_version"] = version
        subnet = self.select_subnet(context, net_id, ip_address, segment_id,
                                    **filters)
        if subnet:
            return [subnet]
        raise exceptions.IpAddressGenerationFailure(net_id=net_id)


class QuarkIpamBOTH(QuarkIpam):
    @classmethod
    def get_name(self):
        return "BOTH"

    def is_strategy_satisfied(self, reallocated_ips, allocate_complete=False):
        req = [4, 6]
        for ip in reallocated_ips:
            if ip is not None:
                req.remove(ip["version"])
        ips_allocated = len(req)
        if ips_allocated == 0:
            return True
        elif ips_allocated == 1 and allocate_complete:
            return True

        return False

    def attempt_to_reallocate_ip(self, context, net_id, port_id,
                                 reuse_after, version=None,
                                 ip_address=None, segment_id=None,
                                 subnets=None, **kwargs):
        both_versions = []
        for ver in (4, 6):
            address = super(QuarkIpamBOTH, self).attempt_to_reallocate_ip(
                context, net_id, port_id, reuse_after, ver, ip_address,
                segment_id, subnets=subnets, **kwargs)
            both_versions.extend(address)
        return both_versions

    def _choose_available_subnet(self, context, net_id, version=None,
                                 segment_id=None, ip_address=None,
                                 reallocated_ips=None):
        both_subnet_versions = []
        need_versions = [4, 6]
        for i in reallocated_ips:
            if i["version"] in need_versions:
                need_versions.remove(i["version"])
        filters = {}
        for ver in need_versions:
            filters["ip_version"] = ver
            sub = self.select_subnet(context, net_id, ip_address, segment_id,
                                     **filters)

            if sub:
                both_subnet_versions.append(sub)
        if not reallocated_ips and not both_subnet_versions:
            raise exceptions.IpAddressGenerationFailure(net_id=net_id)

        return both_subnet_versions


class QuarkIpamBOTHREQ(QuarkIpamBOTH):
    @classmethod
    def get_name(self):
        return "BOTH_REQUIRED"

    def is_strategy_satisfied(self, reallocated_ips, allocate_complete=False):
        req = [4, 6]
        for ip in reallocated_ips:
            if ip is not None:
                req.remove(ip["version"])
            ips_allocated = len(req)
            if ips_allocated == 0:
                return True

        return False

    def _choose_available_subnet(self, context, net_id, version=None,
                                 segment_id=None, ip_address=None,
                                 reallocated_ips=None):
        subnets = super(QuarkIpamBOTHREQ, self)._choose_available_subnet(
            context, net_id, version, segment_id, ip_address, reallocated_ips)

        if len(reallocated_ips) + len(subnets) < 2:
            raise exceptions.IpAddressGenerationFailure(net_id=net_id)
        return subnets


class IpamRegistry(object):
    def __init__(self):
        self.strategies = {
            QuarkIpamANY.get_name(): QuarkIpamANY(),
            QuarkIpamBOTH.get_name(): QuarkIpamBOTH(),
            QuarkIpamBOTHREQ.get_name(): QuarkIpamBOTHREQ()}

    def is_valid_strategy(self, strategy_name):
        if strategy_name in self.strategies:
            return True
        return False

    def get_strategy(self, strategy_name):
        if self.is_valid_strategy(strategy_name):
            return self.strategies[strategy_name]
        fallback = CONF.QUARK.default_ipam_strategy
        LOG.warn("IPAM strategy %s not found, "
                 "using default %s" % (strategy_name, fallback))
        return self.strategies[fallback]


IPAM_REGISTRY = IpamRegistry()
