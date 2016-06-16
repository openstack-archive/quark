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
Quark Pluggable IPAM
"""

import functools
import itertools
import random
import time
import uuid

import netaddr
from neutron.common import exceptions as n_exc_ext
from neutron_lib import exceptions as n_exc
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_db import exception as db_exception
from oslo_log import log as logging
from oslo_utils import timeutils

from quark.billing import notify
from quark.db import api as db_api
from quark.db import ip_types
from quark.db import models
from quark.drivers import floating_ip_registry as registry
from quark import exceptions as q_exc
from quark import network_strategy
from quark import utils

LOG = logging.getLogger(__name__)
CONF = cfg.CONF
STRATEGY = network_strategy.STRATEGY

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
                       " semaphore logic around IPAM")),
    cfg.BoolOpt("ipam_select_subnet_v6_locking",
                default=True,
                help=_("Controls whether or not SELECT ... FOR UPDATE is used"
                       " when retrieving v6 subnets explicitly."))
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
    LOG.info("Using RFC2462 method to generate a v6 with MAC %s" % mac)
    int_val += mac.eui64().value
    int_val ^= MAGIC_INT
    return int_val


def rfc3041_ip(port_id, cidr):
    if not port_id:
        random_stuff = uuid.uuid4()
    else:
        random_stuff = uuid.UUID(port_id)
    random.seed(int(random_stuff))
    int_val = netaddr.IPNetwork(cidr).value
    while True:
        rand_bits = random.getrandbits(64)
        LOG.info("Using RFC3041 method to generate a v6 with bits %s" %
                 rand_bits)
        val = int_val + rand_bits
        val ^= MAGIC_INT
        yield val


def ip_address_failure(network_id):
    if STRATEGY.is_provider_network(network_id):
        return q_exc.ProviderNetworkOutOfIps(net_id=network_id)
    else:
        return n_exc.IpAddressGenerationFailure(net_id=network_id)


def generate_v6(mac, port_id, cidr):
    # NOTE(mdietz): RM10879 - if we don't have a MAC, don't panic, defer to
    #               our magic rfc3041_ip method instead. If an IP is created
    #               by the ip_addresses controller, we wouldn't necessarily
    #               have a MAC to base our generator on in that case for
    #               example.
    if mac is not None:
        addr = rfc2462_ip(mac, cidr)
        yield addr

    for addr in rfc3041_ip(port_id, cidr):
        yield addr


def ipam_logged(fx):
    def wrap(self, *args, **kwargs):
        log = QuarkIPAMLog()
        kwargs['ipam_log'] = log
        try:
            return fx(self, *args, **kwargs)
        finally:
            log.end()
    return wrap


class QuarkIPAMLog(object):
    def __init__(self):
        self.entries = {}
        self.success = True

    def make_entry(self, fx_name):
        if fx_name not in self.entries:
            self.entries[fx_name] = []
        entry = QuarkIPAMLogEntry(self, fx_name)
        self.entries[fx_name].append(entry)
        return entry

    def _output(self, status, time_total, fails, successes):
        statistics = ("TIME:%f ATTEMPTS:%d PASS:%d FAIL:%d" %
                      (time_total, fails + successes, successes, fails))
        if not self.success:
            LOG.warning("STATUS:FAILED %s" % statistics)
        else:
            LOG.debug("STATUS:SUCCESS %s" % statistics)

    def end(self):
        total = 0
        fails = 0
        successes = 0
        for fx, entries in self.entries.items():
            for entry in entries:
                total += entry.get_time()
                if entry.success:
                    successes += 1
                else:
                    fails += 1
        self._output(self.success, total, fails, successes)

    def failed(self):
        self.success = False


class QuarkIPAMLogEntry(object):
    def __init__(self, log, name):
        self.name = name
        self.log = log
        self.start_time = time.time()
        self.success = True

    def failed(self):
        self.success = False

    def end(self):
        self.end_time = time.time()

    def get_time(self):
        if not hasattr(self, 'end_time'):
            return 0
        return self.end_time - self.start_time


class QuarkIpam(object):
    @synchronized(named("allocate_mac_address"))
    def allocate_mac_address(self, context, net_id, port_id, reuse_after,
                             mac_address=None,
                             use_forbidden_mac_range=False):
        if mac_address:
            mac_address = netaddr.EUI(mac_address).value

        kwargs = {"network_id": net_id, "port_id": port_id,
                  "mac_address": mac_address,
                  "use_forbidden_mac_range": use_forbidden_mac_range}
        LOG.info(("Attempting to allocate a new MAC address "
                  "[{0}]").format(utils.pretty_kwargs(**kwargs)))

        for retry in xrange(CONF.QUARK.mac_address_retry_max):
            LOG.info("Attemping to reallocate deallocated MAC (step 1 of 3),"
                     " attempt {0} of {1}".format(
                         retry + 1, CONF.QUARK.mac_address_retry_max))
            try:
                with context.session.begin():
                    transaction = db_api.transaction_create(context)
                update_kwargs = {
                    "deallocated": False,
                    "deallocated_at": None,
                    "transaction_id": transaction.id
                }
                filter_kwargs = {
                    "deallocated": True,
                }
                if mac_address is not None:
                    filter_kwargs["address"] = mac_address
                if reuse_after is not None:
                    filter_kwargs["reuse_after"] = reuse_after
                elevated = context.elevated()
                result = db_api.mac_address_reallocate(
                    elevated, update_kwargs, **filter_kwargs)
                if not result:
                    break

                reallocated_mac = db_api.mac_address_reallocate_find(
                    elevated, transaction.id)
                if reallocated_mac:
                    dealloc = netaddr.EUI(reallocated_mac["address"])
                    LOG.info("Found a suitable deallocated MAC {0}".format(
                        str(dealloc)))
                    LOG.info("MAC assignment for port ID {0} completed "
                             "with address {1}".format(port_id, dealloc))
                    return reallocated_mac
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
                    mac_range = \
                        fn(context, address=mac_address,
                           use_forbidden_mac_range=use_forbidden_mac_range)

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
                        db_api.mac_range_update_set_full(context, rng)
                        LOG.info("MAC range {0} is full".format(rng["cidr"]))
                        continue

                    if mac_address:
                        next_address = mac_address
                    else:
                        next_address = rng["next_auto_assign_mac"]
                        if next_address + 1 > rng["last_address"]:
                            db_api.mac_range_update_set_full(context, rng)
                        else:
                            db_api.mac_range_update_next_auto_assign_mac(
                                context, rng)
                        context.session.refresh(rng)
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

        raise n_exc_ext.MacAddressGenerationFailure(net_id=net_id)

    @synchronized(named("reallocate_ip"))
    def attempt_to_reallocate_ip(self, context, net_id, port_id, reuse_after,
                                 version=None, ip_address=None,
                                 segment_id=None, subnets=None, **kwargs):
        version = version or [4, 6]
        elevated = context.elevated()

        LOG.info("Attempting to reallocate an IP (step 1 of 3) - [{0}]".format(
            utils.pretty_kwargs(network_id=net_id, port_id=port_id,
                                version=version, segment_id=segment_id,
                                subnets=subnets, ip_address=ip_address)))

        if version == 6:
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
        elif segment_id:
            subnets = db_api.subnet_find(elevated,
                                         network_id=net_id,
                                         segment_id=segment_id)
            sub_ids = [s["id"] for s in subnets]
            if not sub_ids:
                LOG.info("No subnets matching segment_id {0} could be "
                         "found".format(segment_id))
                raise ip_address_failure(net_id)

        ip_kwargs = {
            "network_id": net_id,
            "deallocated": True,
            "version": version,
            "lock_id": None,
        }
        if reuse_after is not None:
            ip_kwargs["reuse_after"] = reuse_after
        if ip_address is not None:
            ip_kwargs["ip_address"] = ip_address
            del ip_kwargs["deallocated"]
        if sub_ids:
            ip_kwargs["subnet_id"] = sub_ids

        ipam_log = kwargs.get('ipam_log', None)

        for retry in xrange(CONF.QUARK.ip_address_retry_max):
            attempt = None
            if ipam_log:
                attempt = ipam_log.make_entry("attempt_to_reallocate_ip")
            LOG.info("Attempt {0} of {1}".format(
                retry + 1, CONF.QUARK.ip_address_retry_max))
            try:
                with context.session.begin():
                    transaction = db_api.transaction_create(context)
                m = models.IPAddress
                update_kwargs = {
                    m.transaction_id: transaction.id,
                    m.address_type: kwargs.get("address_type", ip_types.FIXED),
                    m.deallocated: False,
                    m.deallocated_at: None,
                    m.used_by_tenant_id: context.tenant_id,
                    m.allocated_at: timeutils.utcnow(),
                }
                result = db_api.ip_address_reallocate(
                    elevated, update_kwargs, **ip_kwargs)
                if not result:
                    LOG.info("Couldn't update any reallocatable addresses "
                             "given the criteria")
                    if attempt:
                        attempt.failed()
                    break

                updated_address = db_api.ip_address_reallocate_find(
                    elevated, transaction.id)
                if not updated_address:
                    if attempt:
                        attempt.failed()
                    continue

                LOG.info("Address {0} is reallocated".format(
                    updated_address["address_readable"]))
                return [updated_address]
            except Exception:
                if attempt:
                    attempt.failed()
                LOG.exception("Error in reallocate ip...")
            finally:
                if attempt:
                    attempt.end()
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

        if subnet and subnet["ip_policy"]:
            ip_policy_cidrs = subnet["ip_policy"].get_cidrs_ip_set()
        else:
            ip_policy_cidrs = netaddr.IPSet([])

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
                # alexm: instead of notifying billing from here we notify from
                # allocate_ip_address() when it's clear that the IP
                # allocation was successful
        except db_exception.DBDuplicateEntry:
            raise n_exc.IpAddressInUse(ip_address=next_ip, net_id=net_id)
        except db_exception.DBError:
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

        if ip_address:
            LOG.info("IP %s explicitly requested, deferring to standard "
                     "allocation" % ip_address)
            return self._allocate_from_subnet(context, net_id=net_id,
                                              subnet=subnet, port_id=port_id,
                                              reuse_after=reuse_after,
                                              ip_address=ip_address, **kwargs)
        else:
            mac = kwargs.get("mac_address")
            if mac:
                mac = kwargs["mac_address"].get("address")

            if subnet and subnet["ip_policy"]:
                ip_policy_cidrs = subnet["ip_policy"].get_cidrs_ip_set()
            else:
                ip_policy_cidrs = netaddr.IPSet([])

            for tries, ip_address in enumerate(
                    generate_v6(mac, port_id, subnet["cidr"])):

                LOG.info("Attempt {0} of {1}".format(
                    tries + 1, CONF.QUARK.v6_allocation_attempts))

                if tries > CONF.QUARK.v6_allocation_attempts - 1:
                    LOG.info("Exceeded v6 allocation attempts, bailing")
                    raise ip_address_failure(net_id)

                ip_address = netaddr.IPAddress(ip_address).ipv6()
                LOG.info("Generated a new v6 address {0}".format(
                    str(ip_address)))

                if (ip_policy_cidrs is not None and
                        ip_address in ip_policy_cidrs):
                    LOG.info("Address {0} excluded by policy".format(
                        str(ip_address)))
                    continue

                try:
                    with context.session.begin():
                        address = db_api.ip_address_create(
                            context, address=ip_address,
                            subnet_id=subnet["id"],
                            version=subnet["ip_version"], network_id=net_id,
                            address_type=kwargs.get('address_type',
                                                    ip_types.FIXED))
                        # alexm: need to notify from here because this code
                        # does not go through the _allocate_from_subnet() path.
                        notify(context, 'ip.add', address)
                        return address
                except db_exception.DBDuplicateEntry:
                    # This shouldn't ever happen, since we hold a unique MAC
                    # address from the previous IPAM step.
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
        allocated_ips = [ip.get("address_readable") for ip in new_addresses]
        for subnet in subnets:
            if not subnet:
                continue

            if str(ip_address) in allocated_ips:
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

    @ipam_logged
    def allocate_ip_address(self, context, new_addresses, net_id, port_id,
                            reuse_after, segment_id=None, version=None,
                            ip_addresses=None, subnets=None, **kwargs):
        elevated = context.elevated()
        subnets = subnets or []
        ip_addresses = ip_addresses or []

        ipam_log = kwargs.get('ipam_log', None)
        LOG.info("Starting a new IP address(es) allocation. Strategy "
                 "is {0} - [{1}]".format(
                     self.get_name(),
                     utils.pretty_kwargs(network_id=net_id, port_id=port_id,
                                         new_addresses=new_addresses,
                                         ip_addresses=ip_addresses,
                                         subnets=subnets,
                                         segment_id=segment_id,
                                         version=version)))

        def _try_reallocate_ip_address(ipam_log, ip_addr=None):
            new_addresses.extend(self.attempt_to_reallocate_ip(
                context, net_id, port_id, reuse_after, version=version,
                ip_address=ip_addr, segment_id=segment_id, subnets=subnets,
                **kwargs))

        def _try_allocate_ip_address(ipam_log, ip_addr=None, sub=None):
            for retry in xrange(CONF.QUARK.ip_address_retry_max):
                attempt = None
                if ipam_log:
                    attempt = ipam_log.make_entry("_try_allocate_ip_address")
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
                    if attempt:
                        LOG.debug("ATTEMPT FAILED")
                        attempt.failed()
                    remaining = CONF.QUARK.ip_address_retry_max - retry - 1
                    if remaining > 0:
                        LOG.info("{0} retries remain, retrying...".format(
                            remaining))
                    else:
                        LOG.info("No retries remaing, bailing")
                    continue
                finally:
                    if attempt:
                        attempt.end()

                break

        ip_addresses = [netaddr.IPAddress(ip_address)
                        for ip_address in ip_addresses]

        if ip_addresses:
            for ip_address in ip_addresses:
                _try_reallocate_ip_address(ipam_log, ip_address)
        else:
            _try_reallocate_ip_address(ipam_log)

        if self.is_strategy_satisfied(new_addresses):
            return
        else:
            LOG.info("Reallocated addresses {0} but still need more addresses "
                     "to satisfy strategy {1}. Falling back to creating "
                     "IPs".format(new_addresses, self.get_name()))

        if ip_addresses or subnets:
            for ip_address, subnet in itertools.izip_longest(ip_addresses,
                                                             subnets):
                _try_allocate_ip_address(ipam_log, ip_address, subnet)
        else:
            _try_allocate_ip_address(ipam_log)

        if self.is_strategy_satisfied(new_addresses, allocate_complete=True):
            # Only notify when all went well
            for address in new_addresses:
                notify(context, 'ip.add', address)
            LOG.info("IPAM for port ID {0} completed with addresses "
                     "{1}".format(port_id,
                                  [a["address_readable"]
                                   for a in new_addresses]))
            return
        ipam_log.failed()

        raise ip_address_failure(net_id)

    def deallocate_ip_address(self, context, address):
        if address["version"] == 6:
            db_api.ip_address_delete(context, address)
        else:
            address["deallocated"] = 1
            address["address_type"] = None

        notify(context, 'ip.delete', address, send_usage=True)

    def deallocate_ips_by_port(self, context, port=None, **kwargs):
        ips_to_remove = []
        for addr in port["ip_addresses"]:
            if "ip_address" in kwargs:
                ip = kwargs["ip_address"]
                if ip != netaddr.IPAddress(int(addr["address"])):
                    continue

            # Note: only deallocate ip if this is the
            # only port mapped
            ips_to_remove.append(addr)

        port["ip_addresses"] = list(
            set(port["ip_addresses"]) - set(ips_to_remove))

        # NCP-1541: We don't need to track v6 IPs the same way. Also, we can't
        # delete them until we've removed the FK on the assoc record first, so
        # we have to flush the current state of the transaction.
        # NOTE(mdietz): this does increase traffic to the db because we need
        #               to flush, fetch the records again and potentially make
        #               another trip to deallocate each IP, but keeping our
        #               indices smaller probably provides more value than the
        #               cost
        # NOTE(aquillin): For floating IPs associated with the port, we do not
        #                 want to deallocate the IP or disassociate the IP from
        #                 the tenant, instead we will disassociate floating's
        #                 fixed IP address.
        context.session.flush()
        deallocated_ips = []
        flip = None
        for ip in ips_to_remove:
            if ip["address_type"] in (ip_types.FLOATING, ip_types.SCALING):
                flip = ip
            else:
                if len(ip["ports"]) == 0:
                    self.deallocate_ip_address(context, ip)
                    deallocated_ips.append(ip.id)
        if flip:
            if flip.fixed_ips and len(flip.fixed_ips) == 1:
                # This is a FLIP or SCIP that is only associated with one
                # port and fixed_ip, so we can safely just disassociate all
                # and remove the flip from unicorn.
                db_api.floating_ip_disassociate_all_fixed_ips(context, flip)
                # NOTE(blogan): I'm not too happy about having do another
                # flush but some test runs showed inconsistent state based on
                # SQLAlchemy caching.
                context.session.add(flip)
                context.session.flush()
                notify(context, 'ip.disassociate', flip)
                driver = registry.DRIVER_REGISTRY.get_driver()
                driver.remove_floating_ip(flip)
            elif len(flip.fixed_ips) > 1:
                # This is a SCIP and we need to diassociate the one fixed_ip
                # from the SCIP and update unicorn with the remaining
                # ports and fixed_ips
                remaining_fixed_ips = []
                for fix_ip in flip.fixed_ips:
                    if fix_ip.id in deallocated_ips:
                        db_api.floating_ip_disassociate_fixed_ip(
                            context, flip, fix_ip)
                        context.session.add(flip)
                        context.session.flush()
                        notify(context, 'ip.disassociate', flip)
                    else:
                        remaining_fixed_ips.append(fix_ip)
                port_fixed_ips = {}
                for fix_ip in remaining_fixed_ips:
                    # NOTE(blogan): Since this is the flip's fixed_ips it
                    # should be safe to assume there is only one port
                    # associated with it.
                    remaining_port = fix_ip.ports[0]
                    port_fixed_ips[remaining_port.id] = {
                        'port': remaining_port,
                        'fixed_ip': fix_ip
                    }
                driver = registry.DRIVER_REGISTRY.get_driver()
                driver.update_floating_ip(flip, port_fixed_ips)

    # NCP-1509(roaet):
    # - started using admin_context due to tenant not claiming when realloc
    def deallocate_mac_address(self, context, address):
        admin_context = context.elevated()
        mac = db_api.mac_address_find(admin_context, address=address,
                                      scope=db_api.ONE)
        if not mac:
            raise q_exc.MacAddressNotFound(
                mac_address_id=address,
                readable_mac=netaddr.EUI(address))

        if (mac["mac_address_range"] is None or
                mac["mac_address_range"]["do_not_use"]):
            db_api.mac_address_delete(admin_context, mac)
        else:
            db_api.mac_address_update(admin_context, mac, deallocated=True,
                                      deallocated_at=timeutils.utcnow())

    def _select_subnet(self, context, net_id, ip_address, segment_id,
                       subnet_ids, **filters):
        # NCP-1480: Don't need to lock V6 subnets, since we don't use
        # next_auto_assign_ip for them. We already uniquely identified
        # the V6 we're going to get by generating a MAC in a previous step.
        # Also note that this only works under BOTH or BOTH_REQUIRED. ANY
        # does not pass an ip_version
        lock_subnets = True
        if (not CONF.QUARK.ipam_select_subnet_v6_locking and
                "ip_version" in filters and
                int(filters["ip_version"]) == 6):
            lock_subnets = False

        select_api = db_api.subnet_find_ordered_by_most_full
        # TODO(mdietz): Add configurable, alternate subnet selection here
        subnets = select_api(context, net_id, lock_subnets=lock_subnets,
                             segment_id=segment_id, scope=db_api.ALL,
                             subnet_id=subnet_ids, **filters)

        if not subnets:
            LOG.info("No subnets found given the search criteria!")
            return

        # TODO(mdietz): Making this into an iterator because we want to move
        #               to selecting 1 subnet at a time and paginating rather
        #               than the bulk fetch. Without locks, we need to
        #               minimize looking at stale data to save ourselves
        #               some retries. Getting then 1 at a time will
        #               facilitate this.
        for subnet, ips_in_subnet in subnets:
            yield subnet, ips_in_subnet

    def _should_mark_subnet_full(self, context, subnet, ipnet, ip_address,
                                 ips_in_subnet):
        ip = subnet["next_auto_assign_ip"]
        # NOTE(mdietz): When atomically updated, this probably
        #               doesn't need the lower bounds check but
        #               I'm not comfortable removing it yet.
        if (subnet["ip_version"] == 4 and ip < subnet["first_ip"] or
                ip > subnet["last_ip"]):
            return True

        ip_policy = None
        if not ip_address:
            # Policies don't prevent explicit assignment, so we only
            # need to check if we're allocating a new IP
            ip_policy = subnet.get("ip_policy")

        policy_size = ip_policy["size"] if ip_policy else 0

        if ipnet.size > (ips_in_subnet + policy_size - 1):
            return False
        return True

    def _ip_in_subnet(self, subnet, subnet_ids, ipnet, ip_address):
        if ip_address:
            requested_ip = netaddr.IPAddress(ip_address)
            if ipnet.version == 4 and requested_ip.version != 4:
                requested_ip = requested_ip.ipv4()
            if requested_ip not in ipnet:
                if subnet_ids is not None:
                    LOG.info("Requested IP {0} not in subnet {1}, "
                             "retrying".format(str(requested_ip),
                                               str(ipnet)))
                    raise q_exc.IPAddressNotInSubnet(
                        ip_addr=ip_address, subnet_id=subnet["id"])
                return False
        return True

    def select_subnet(self, context, net_id, ip_address, segment_id,
                      subnet_ids=None, **filters):
        LOG.info("Selecting subnet(s) - (Step 2 of 3) [{0}]".format(
            utils.pretty_kwargs(network_id=net_id, ip_address=ip_address,
                                segment_id=segment_id, subnet_ids=subnet_ids,
                                ip_version=filters.get("ip_version"))))

        # TODO(mdietz): Invert the iterator and the session, should only be
        #               one subnet per attempt. We should also only be fetching
        #               the subnet and usage when we need to. Otherwise
        #               we're locking every subnet for a segment, and once
        #               we stop locking, we're looking at stale data.
        with context.session.begin():
            for subnet, ips_in_subnet in self._select_subnet(context, net_id,
                                                             ip_address,
                                                             segment_id,
                                                             subnet_ids,
                                                             **filters):
                if subnet is None:
                    continue
                ipnet = netaddr.IPNetwork(subnet["cidr"])
                LOG.info("Trying subnet ID: {0} - CIDR: {1}".format(
                    subnet["id"], subnet["_cidr"]))

                if not self._ip_in_subnet(subnet, subnet_ids, ipnet,
                                          ip_address):
                    continue

                if self._should_mark_subnet_full(context, subnet, ipnet,
                                                 ip_address, ips_in_subnet):
                    LOG.info("Marking subnet {0} as full".format(subnet["id"]))
                    updated = db_api.subnet_update_set_full(context, subnet)

                    # Ensure the session is aware of the changes to the subnet
                    if updated:
                        context.session.refresh(subnet)
                    continue

                if not ip_address and subnet["ip_version"] == 4:
                    auto_inc = db_api.subnet_update_next_auto_assign_ip
                    updated = auto_inc(context, subnet)

                    if updated:
                        context.session.refresh(subnet)
                    else:
                        # This means the subnet was marked full
                        # while we were checking out policies.
                        # Fall out and go back to the outer retry
                        # loop.
                        return

                LOG.info("Subnet {0} - {1} {2} looks viable, "
                         "returning".format(subnet["id"], subnet["_cidr"],
                                            subnet["next_auto_assign_ip"]))
                return subnet


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
        raise ip_address_failure(net_id)


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
        ip_address_version = 4 if not ip_address else ip_address.version
        # NOTE(quade): We do not attempt to reallocate ipv6, so just return
        if ip_address_version == 6:
            return []
        return super(QuarkIpamBOTH, self).attempt_to_reallocate_ip(
            context, net_id, port_id, reuse_after, ip_address_version,
            ip_address, segment_id, subnets=subnets, **kwargs)

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
            raise ip_address_failure(net_id)

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
            raise ip_address_failure(net_id)
        return subnets


class IronicIpam(QuarkIpam):
    """IPAM base class for the Ironic driver.

    The idea here is that there are many small subnets created for a
    particular segment for a provider network. The Ironic IPAM
    family selects unused ones, and only allows a single allocation
    per subnet.
    """
    def _select_subnet(self, context, net_id, ip_address, segment_id,
                       subnet_ids, **filters):

        lock_subnets = True

        select_api = db_api.subnet_find_unused
        subnets = select_api(context, net_id, lock_subnets=lock_subnets,
                             segment_id=segment_id, scope=db_api.ALL,
                             subnet_id=subnet_ids, **filters)

        if not subnets:
            LOG.info("No subnets found given the search criteria!")
            return

        for subnet, ips_in_subnet in subnets:
            # make sure we don't select subnets that have allocated ips.
            if ips_in_subnet:
                continue
            yield subnet, ips_in_subnet


class IronicIpamANY(IronicIpam, QuarkIpamANY):
    @classmethod
    def get_name(self):
        return "IRONIC_ANY"


class IronicIpamBOTH(IronicIpam, QuarkIpamBOTH):
    @classmethod
    def get_name(self):
        return "IRONIC_BOTH"


class IronicIpamBOTHREQ(IronicIpam, QuarkIpamBOTHREQ):
    @classmethod
    def get_name(self):
        return "IRONIC_BOTH_REQUIRED"


class IpamRegistry(object):
    def __init__(self):
        self.strategies = {
            QuarkIpamANY.get_name(): QuarkIpamANY(),
            QuarkIpamBOTH.get_name(): QuarkIpamBOTH(),
            QuarkIpamBOTHREQ.get_name(): QuarkIpamBOTHREQ(),
            IronicIpamANY.get_name(): IronicIpamANY(),
            IronicIpamBOTH.get_name(): IronicIpamBOTH(),
            IronicIpamBOTHREQ.get_name(): IronicIpamBOTHREQ()
        }

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
