# Copyright 2014 Rackspace Hosting Inc.
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

import netaddr
from neutron.common import exceptions as n_exc_ext
from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class AllocationPools(object):
    def __init__(self, subnet_cidr, pools=None, policies=None):
        self._exclude_cidrs = None
        self._subnet_cidr = netaddr.IPNetwork(subnet_cidr)
        self._alloc_pools = pools
        version = self._subnet_cidr.version
        self._subnet_first_ip = netaddr.IPAddress(
            self._subnet_cidr.first, version=version)
        self._subnet_last_ip = netaddr.IPAddress(
            self._subnet_cidr.last, version=version)

        # If passed an empty list, the entire subnet is unallocatable.
        # If None is passed, the entire subnet is allocatable
        if self._alloc_pools is None:
            self._alloc_pools = [
                {"start": self._subnet_first_ip,
                 "end": self._subnet_last_ip}]
        self._policies = policies or []

    def __len__(self):
        return len(self._alloc_pools)

    # Note(asadoughi): Copied from neutron/db/db_base_plugin_v2.py
    def _validate_allocation_pools(self):
        """Validate IP allocation pools.

        Verify start and end address for each allocation pool are valid,
        ie: constituted by valid and appropriately ordered IP addresses.
        Also, verify pools do not overlap among themselves.
        Finally, verify that each range fall within the subnet's CIDR.
        """
        ip_pools = self._alloc_pools
        subnet_cidr = self._subnet_cidr

        LOG.debug(_("Performing IP validity checks on allocation pools"))
        ip_sets = []
        for ip_pool in ip_pools:
            try:
                start_ip = netaddr.IPAddress(ip_pool['start'])
                end_ip = netaddr.IPAddress(ip_pool['end'])
            except netaddr.AddrFormatError:
                LOG.info(_("Found invalid IP address in pool: "
                           "%(start)s - %(end)s:"),
                         {'start': ip_pool['start'],
                          'end': ip_pool['end']})
                raise n_exc_ext.InvalidAllocationPool(pool=ip_pool)
            if (start_ip.version != self._subnet_cidr.version or
                    end_ip.version != self._subnet_cidr.version):
                LOG.info(_("Specified IP addresses do not match "
                           "the subnet IP version"))
                raise n_exc_ext.InvalidAllocationPool(pool=ip_pool)
            if end_ip < start_ip:
                LOG.info(_("Start IP (%(start)s) is greater than end IP "
                           "(%(end)s)"),
                         {'start': ip_pool['start'], 'end': ip_pool['end']})
                raise n_exc_ext.InvalidAllocationPool(pool=ip_pool)
            if (start_ip < self._subnet_first_ip or
                    end_ip > self._subnet_last_ip):
                LOG.info(_("Found pool larger than subnet "
                           "CIDR:%(start)s - %(end)s"),
                         {'start': ip_pool['start'],
                          'end': ip_pool['end']})
                raise n_exc_ext.OutOfBoundsAllocationPool(
                    pool=ip_pool,
                    subnet_cidr=subnet_cidr)
            # Valid allocation pool
            # Create an IPSet for it for easily verifying overlaps
            ip_sets.append(netaddr.IPSet(netaddr.IPRange(
                ip_pool['start'],
                ip_pool['end']).cidrs()))

        LOG.debug(_("Checking for overlaps among allocation pools "
                    "and gateway ip"))
        ip_ranges = ip_pools[:]

        # Use integer cursors as an efficient way for implementing
        # comparison and avoiding comparing the same pair twice
        for l_cursor in xrange(len(ip_sets)):
            for r_cursor in xrange(l_cursor + 1, len(ip_sets)):
                if ip_sets[l_cursor] & ip_sets[r_cursor]:
                    l_range = ip_ranges[l_cursor]
                    r_range = ip_ranges[r_cursor]
                    LOG.info(_("Found overlapping ranges: %(l_range)s and "
                               "%(r_range)s"),
                             {'l_range': l_range, 'r_range': r_range})
                    raise n_exc_ext.OverlappingAllocationPools(
                        pool_1=l_range,
                        pool_2=r_range,
                        subnet_cidr=subnet_cidr)

    def _build_excludes(self):
        self._validate_allocation_pools()
        subnet_net = netaddr.IPNetwork(self._subnet_cidr)
        version = subnet_net.version
        cidrset = netaddr.IPSet(
            netaddr.IPRange(
                netaddr.IPAddress(subnet_net.first, version=version),
                netaddr.IPAddress(subnet_net.last, version=version)).cidrs())

        if isinstance(self._alloc_pools, list):
            for p in self._alloc_pools:
                start = netaddr.IPAddress(p["start"])
                end = netaddr.IPAddress(p["end"])
                cidrset -= netaddr.IPSet(netaddr.IPRange(
                    netaddr.IPAddress(start),
                    netaddr.IPAddress(end)).cidrs())
        elif self._alloc_pools is None:
            # Empty list is completely unallocatable, None is fully
            # allocatable
            cidrset = netaddr.IPSet()

        for p in self._policies:
            cidrset.add(netaddr.IPNetwork(p))

        self._exclude_cidrs = cidrset

    def _refresh_excludes(self):
        if not self._exclude_cidrs:
            self._build_excludes()

    def add_pool(self, pool):
        self._exclude_cidrs = None
        self._alloc_pools.append(pool)

    def add_policy(self, policy):
        self._exclude_cidrs = None
        self._policies.append(policy)

    def validate_gateway_excluded(self, gateway_ip):
        self._refresh_excludes()
        gateway_ip_addr = netaddr.IPAddress(gateway_ip)
        if gateway_ip_addr in self._subnet_cidr:
            if (not self._exclude_cidrs or
                    (self._exclude_cidrs and gateway_ip_addr
                     not in self._exclude_cidrs)):
                raise n_exc_ext.GatewayConflictWithAllocationPools(
                    ip_address=gateway_ip, pool=self._alloc_pools)

    def get_policy_cidrs(self):
        self._refresh_excludes()
        return [str(c) for c in self._exclude_cidrs.iter_cidrs()]
