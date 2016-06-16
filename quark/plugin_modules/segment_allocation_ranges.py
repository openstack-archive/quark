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

from neutron_lib import exceptions as n_exc
from oslo_log import log as logging

from quark.db import api as db_api
from quark import exceptions as q_exc
from quark import plugin_views as v

from quark import segment_allocations

SA_REGISTRY = segment_allocations.REGISTRY

LOG = logging.getLogger(__name__)


def get_segment_allocation_range(context, id, fields=None):
    LOG.info("get_segment_allocation_range %s for tenant %s fields %s" %
             (id, context.tenant_id, fields))

    if not context.is_admin:
        raise n_exc.NotAuthorized()

    sa_range = db_api.segment_allocation_range_find(
        context, id=id, scope=db_api.ONE)

    if not sa_range:
        raise q_exc.SegmentAllocationRangeNotFound(
            segment_allocation_range_id=id)

    # Count up allocations so we can calculate how many are free.
    allocs = db_api.segment_allocation_find(
        context,
        segment_allocation_range_id=sa_range["id"],
        deallocated=False).count()
    return v._make_segment_allocation_range_dict(
        sa_range, allocations=allocs)


def get_segment_allocation_ranges(context, **filters):
    LOG.info("get_segment_allocation_ranges for tenant %s" % context.tenant_id)
    if not context.is_admin:
        raise n_exc.NotAuthorized()

    sa_ranges = db_api.segment_allocation_range_find(
        context, scope=db_api.ALL, **filters)
    return [v._make_segment_allocation_range_dict(m) for m in sa_ranges]


def create_segment_allocation_range(context, sa_range):
    LOG.info("create_segment_allocation_range for tenant %s"
             % context.tenant_id)
    if not context.is_admin:
        raise n_exc.NotAuthorized()

    sa_range = sa_range.get("segment_allocation_range")
    if not sa_range:
        raise n_exc.BadRequest(resource="segment_allocation_range",
                               msg=("segment_allocation_range not in "
                                    "request body."))

    # TODO(morgabra) Figure out how to get the api extension to validate this
    # for us.
    # parse required fields
    for k in ["first_id", "last_id", "segment_id", "segment_type"]:
        sa_range[k] = sa_range.get(k, None)
        if sa_range[k] is None:
            raise n_exc.BadRequest(
                resource="segment_allocation_range",
                msg=("Missing required key %s in request body." % (k)))

    # parse optional fields
    for k in ["do_not_use"]:
        sa_range[k] = sa_range.get(k, None)

    # use the segment registry to validate and create/populate the range
    if not SA_REGISTRY.is_valid_strategy(sa_range["segment_type"]):
        raise n_exc.BadRequest(
            resource="segment_allocation_range",
            msg=("Unknown segment type '%s'" % (k)))
    strategy = SA_REGISTRY.get_strategy(sa_range["segment_type"])

    # Create the new range
    with context.session.begin():
        new_range = strategy.create_range(context, sa_range)

    # Bulk-populate the range, this could take a while for huge ranges
    # (millions) so we do this in chunks outside the transaction. That
    # means we need to rollback the range creation if it fails for
    # whatever reason (and it will cascade delete any added allocations)
    try:
        strategy.populate_range(context, new_range)
    except Exception:
        LOG.exception("Failed to populate segment allocation range.")
        delete_segment_allocation_range(context, new_range["id"])
        raise

    return v._make_segment_allocation_range_dict(new_range)


def _delete_segment_allocation_range(context, sa_range):

    allocs = db_api.segment_allocation_find(
        context,
        segment_allocation_range_id=sa_range["id"],
        deallocated=False).count()

    if allocs:
        raise q_exc.SegmentAllocationRangeInUse(
            segment_allocation_range_id=sa_range["id"])
    db_api.segment_allocation_range_delete(context, sa_range)


def delete_segment_allocation_range(context, sa_id):
    """Delete a segment_allocation_range.

    : param context: neutron api request context
    : param id: UUID representing the segment_allocation_range to delete.
    """
    LOG.info("delete_segment_allocation_range %s for tenant %s" %
             (sa_id, context.tenant_id))
    if not context.is_admin:
        raise n_exc.NotAuthorized()

    with context.session.begin():
        sa_range = db_api.segment_allocation_range_find(
            context, id=sa_id, scope=db_api.ONE)
        if not sa_range:
            raise q_exc.SegmentAllocationRangeNotFound(
                segment_allocation_range_id=sa_id)
        _delete_segment_allocation_range(context, sa_range)
