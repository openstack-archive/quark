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

from collections import defaultdict
import datetime
import json
import sys

import netaddr
from neutron.common import config
from neutron.db import api as neutron_db_api
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
from sqlalchemy import and_, or_, func, not_

from quark.db import models

LOG = logging.getLogger(__name__)


def main():
    config.init(sys.argv[1:])
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))
    config.setup_logging()

    public_network_id = "00000000-0000-0000-0000-000000000000"
    ip_availability = get_ip_availability(network_id=public_network_id,
                                          ip_version=4)
    print(json.dumps(ip_availability))


def get_ip_availability(**kwargs):
    LOG.debug("Begin querying %s" % kwargs)
    used_ips = get_used_ips(neutron_db_api.get_session(use_slave=True),
                            **kwargs)
    unused_ips = get_unused_ips(neutron_db_api.get_session(use_slave=True),
                                used_ips, **kwargs)
    LOG.debug("End querying")
    return dict(used=used_ips, unused=unused_ips)


def _convert_kwargs_values_into_tuples(f):
    def wrapped(*args, **kwargs):
        for key, value in kwargs.iteritems():
            if value is None:
                continue
            if not isinstance(value, list) and not isinstance(value, tuple):
                kwargs[key] = (value,)
        return f(*args, **kwargs)
    return wrapped


@_convert_kwargs_values_into_tuples
def _filter(query,
            network_id=None, segment_id=None, ip_version=None, subnet_id=None):
    query = query.filter(or_(models.Subnet.do_not_use.is_(None),
                             models.Subnet.do_not_use == 0))
    if network_id is not None:
        query = query.filter(models.Subnet.network_id.in_(network_id))
    if segment_id is not None:
        query = query.filter(models.Subnet.segment_id.in_(segment_id))
    if ip_version is not None:
        query = query.filter(models.Subnet.ip_version.in_(ip_version))
    if subnet_id is not None:
        query = query.filter(models.Subnet.id.in_(subnet_id))
    return query


def get_used_ips(session, **kwargs):
    """Returns dictionary with keys segment_id and value used IPs count.

    Used IP address count is determined by:
    - allocated IPs
    - deallocated IPs whose `deallocated_at` is within the `reuse_after`
    window compared to the present time, excluding IPs that are accounted for
    in the current IP policy (because IP policy is mutable and deallocated IPs
    are not checked nor deleted on IP policy creation, thus deallocated IPs
    that don't fit the current IP policy can exist in the neutron database).
    """
    LOG.debug("Getting used IPs...")
    with session.begin():
        query = session.query(
            models.Subnet.segment_id,
            func.count(models.IPAddress.address))
        query = query.group_by(models.Subnet.segment_id)
        query = _filter(query, **kwargs)

        reuse_window = timeutils.utcnow() - datetime.timedelta(
            seconds=cfg.CONF.QUARK.ipam_reuse_after)
        # NOTE(asadoughi): This is an outer join instead of a regular join
        # to include subnets with zero IP addresses in the database.
        query = query.outerjoin(
            models.IPAddress,
            and_(models.Subnet.id == models.IPAddress.subnet_id,
                 or_(not_(models.IPAddress.lock_id.is_(None)),
                     models.IPAddress._deallocated.is_(None),
                     models.IPAddress._deallocated == 0,
                     models.IPAddress.deallocated_at > reuse_window)))

        query = query.outerjoin(
            models.IPPolicyCIDR,
            and_(
                models.Subnet.ip_policy_id == models.IPPolicyCIDR.ip_policy_id,
                models.IPAddress.address >= models.IPPolicyCIDR.first_ip,
                models.IPAddress.address <= models.IPPolicyCIDR.last_ip))
        # NOTE(asadoughi): (address is allocated) OR
        # (address is deallocated and not inside subnet's IP policy)
        query = query.filter(or_(
            models.IPAddress._deallocated.is_(None),
            models.IPAddress._deallocated == 0,
            models.IPPolicyCIDR.id.is_(None)))

        ret = ((segment_id, address_count)
               for segment_id, address_count in query.all())
        return dict(ret)


def get_unused_ips(session, used_ips_counts, **kwargs):
    """Returns dictionary with key segment_id, and value unused IPs count.

    Unused IP address count is determined by:
    - adding subnet's cidr's size
    - subtracting IP policy exclusions on subnet
    - subtracting used ips per segment
    """
    LOG.debug("Getting unused IPs...")
    with session.begin():
        query = session.query(
            models.Subnet.segment_id,
            models.Subnet)
        query = _filter(query, **kwargs)
        query = query.group_by(models.Subnet.segment_id, models.Subnet.id)

        ret = defaultdict(int)
        for segment_id, subnet in query.all():
            net_size = netaddr.IPNetwork(subnet._cidr).size
            ip_policy = subnet["ip_policy"] or {"size": 0}
            ret[segment_id] += net_size - ip_policy["size"]

        for segment_id in used_ips_counts:
            ret[segment_id] -= used_ips_counts[segment_id]

        return ret
