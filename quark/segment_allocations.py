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
Provide strategies for allocating network segments. (vlan, vxlan, etc)
"""
from quark.db import api as db_api
from quark import exceptions as q_exc

from oslo_log import log as logging
from oslo_utils import timeutils

import itertools
import random

LOG = logging.getLogger(__name__)


class BaseSegmentAllocation(object):

    segment_type = None

    def _validate_range(self, context, sa_range):
        raise NotImplementedError()

    def _chunks(self, iterable, chunk_size):
        """Chunks data into chunk with size<=chunk_size."""
        iterator = iter(iterable)
        chunk = list(itertools.islice(iterator, 0, chunk_size))
        while chunk:
            yield chunk
            chunk = list(itertools.islice(iterator, 0, chunk_size))

    def _check_collisions(self, new_range, existing_ranges):
        """Check for overlapping ranges."""
        def _contains(num, r1):
            return (num >= r1[0] and
                    num <= r1[1])

        def _is_overlap(r1, r2):
            return (_contains(r1[0], r2) or
                    _contains(r1[1], r2) or
                    _contains(r2[0], r1) or
                    _contains(r2[1], r1))

        for existing_range in existing_ranges:
            if _is_overlap(new_range, existing_range):
                return True
        return False

    def _make_segment_allocation_dict(self, id, sa_range):
        return dict(
            id=id,
            segment_id=sa_range["segment_id"],
            segment_type=sa_range["segment_type"],
            segment_allocation_range_id=sa_range["id"],
            deallocated=True
        )

    def _populate_range(self, context, sa_range):
        first_id = sa_range["first_id"]
        last_id = sa_range["last_id"]
        id_range = xrange(first_id, last_id + 1)

        LOG.info("Starting segment allocation population for "
                 "range:%s size:%s."
                 % (sa_range["id"], len(id_range)))

        total_added = 0
        for chunk in self._chunks(id_range, 5000):
            sa_dicts = []
            for segment_id in chunk:
                sa_dict = self._make_segment_allocation_dict(
                    segment_id, sa_range)
                sa_dicts.append(sa_dict)
            db_api.segment_allocation_range_populate_bulk(context, sa_dicts)
            context.session.flush()
            total_added = total_added + len(sa_dicts)

            LOG.info("Populated %s/%s segment ids for range:%s"
                     % (total_added, len(id_range), sa_range["id"]))

        LOG.info("Finished segment allocation population for "
                 "range:%s size:%s."
                 % (sa_range["id"], len(id_range)))

    def _create_range(self, context, sa_range):
        with context.session.begin(subtransactions=True):
            # Validate any range-specific things, like min/max ids.
            self._validate_range(context, sa_range)

            # Check any existing ranges for this segment for collisions
            segment_id = sa_range["segment_id"]
            segment_type = sa_range["segment_type"]

            filters = {"segment_id": segment_id,
                       "segment_type": segment_type}
            existing_ranges = db_api.segment_allocation_range_find(
                context, lock_mode=True, scope=db_api.ALL, **filters)

            collides = self._check_collisions(
                (sa_range["first_id"], sa_range["last_id"]),
                [(r["first_id"], r["last_id"]) for r in existing_ranges])

            if collides:
                raise q_exc.InvalidSegmentAllocationRange(
                    msg=("The specified allocation collides with existing "
                         "range"))

            return db_api.segment_allocation_range_create(
                context, **sa_range)

    def create_range(self, context, sa_range):
        return self._create_range(context, sa_range)

    def populate_range(self, context, sa_range):
        return self._populate_range(context, sa_range)

    def _try_allocate(self, context, segment_id, network_id):
        """Find a deallocated network segment id and reallocate it.

        NOTE(morgabra) This locks the segment table, but only the rows
        in use by the segment, which is pretty handy if we ever have
        more than 1 segment or segment type.
        """
        LOG.info("Attempting to allocate segment for network %s "
                 "segment_id %s segment_type %s"
                 % (network_id, segment_id, self.segment_type))

        filter_dict = {
            "segment_id": segment_id,
            "segment_type": self.segment_type,
            "do_not_use": False
        }
        available_ranges = db_api.segment_allocation_range_find(
            context, scope=db_api.ALL, **filter_dict)
        available_range_ids = [r["id"] for r in available_ranges]

        try:
            with context.session.begin(subtransactions=True):
                # Search for any deallocated segment ids for the
                # given segment.
                filter_dict = {
                    "deallocated": True,
                    "segment_id": segment_id,
                    "segment_type": self.segment_type,
                    "segment_allocation_range_ids": available_range_ids
                }

                # NOTE(morgabra) We select 100 deallocated segment ids from
                # the table here, and then choose 1 randomly. This is to help
                # alleviate the case where an uncaught exception might leave
                # an allocation active on a remote service but we do not have
                # a record of it locally. If we *do* end up choosing a
                # conflicted id, the caller should simply allocate another one
                # and mark them all as reserved. If a single object has
                # multiple reservations on the same segment, they will not be
                # deallocated, and the operator must resolve the conficts
                # manually.
                allocations = db_api.segment_allocation_find(
                    context, lock_mode=True, **filter_dict).limit(100).all()

                if allocations:
                    allocation = random.choice(allocations)

                    # Allocate the chosen segment.
                    update_dict = {
                        "deallocated": False,
                        "deallocated_at": None,
                        "network_id": network_id
                    }
                    allocation = db_api.segment_allocation_update(
                        context, allocation, **update_dict)
                    LOG.info("Allocated segment %s for network %s "
                             "segment_id %s segment_type %s"
                             % (allocation["id"], network_id, segment_id,
                                self.segment_type))
                    return allocation
        except Exception:
            LOG.exception("Error in segment reallocation.")

        LOG.info("Cannot find reallocatable segment for network %s "
                 "segment_id %s segment_type %s"
                 % (network_id, segment_id, self.segment_type))

    def allocate(self, context, segment_id, network_id):
        allocation = self._try_allocate(
            context, segment_id, network_id)

        if allocation:
            return allocation

        raise q_exc.SegmentAllocationFailure(
            segment_id=segment_id, segment_type=self.segment_type)

    def _try_deallocate(self, context, segment_id, network_id):
        LOG.info("Attempting to deallocate segment for network %s "
                 "segment_id %s segment_type %s"
                 % (network_id, segment_id, self.segment_type))

        with context.session.begin(subtransactions=True):
            filter_dict = {
                "deallocated": False,
                "segment_id": segment_id,
                "segment_type": self.segment_type,
                "network_id": network_id
            }

            allocations = db_api.segment_allocation_find(
                context, **filter_dict).all()

            if not allocations:
                LOG.info("Could not find allocated segment for network %s "
                         "segment_id %s segment_type %s for deallocate."
                         % (network_id, segment_id, self.segment_type))
                return

            if len(allocations) > 1:
                LOG.error("Found multiple allocated segments for network %s "
                          "segment_id %s segment_type %s for deallocate. "
                          "Refusing to deallocate, these allocations are now "
                          "orphaned."
                          % (network_id, segment_id, self.segment_type))
                return

            allocation = allocations[0]
            # Deallocate the found segment.
            update_dict = {
                "deallocated": True,
                "deallocated_at": timeutils.utcnow(),
                "network_id": None
            }
            allocation = db_api.segment_allocation_update(
                context, allocation, **update_dict)

            LOG.info("Deallocated %s allocated segment(s) for network %s "
                     "segment_id %s segment_type %s"
                     % (len(allocations), network_id, segment_id,
                        self.segment_type))

    def deallocate(self, context, segment_id, network_id):
        self._try_deallocate(context, segment_id, network_id)


class VXLANSegmentAllocation(BaseSegmentAllocation):

    VXLAN_MIN = 1
    VXLAN_MAX = (2 ** 24) - 1

    segment_type = 'vxlan'

    def _validate_range(self, context, sa_range):
        # Validate that the range is legal and makes sense.
        try:
            first_id = sa_range["first_id"]
            last_id = sa_range["last_id"]
            first_id, last_id = (int(first_id), int(last_id))
            assert first_id >= self.VXLAN_MIN
            assert last_id <= self.VXLAN_MAX
            assert first_id <= last_id
        except Exception:
            raise q_exc.InvalidSegmentAllocationRange(
                msg="The specified allocation range is invalid")


class SegmentAllocationRegistry(object):
    def __init__(self):
        self.strategies = {
            VXLANSegmentAllocation.segment_type: VXLANSegmentAllocation(),
        }

    def is_valid_strategy(self, strategy_name):
        if strategy_name in self.strategies:
            return True
        return False

    def get_strategy(self, strategy_name):
        if self.is_valid_strategy(strategy_name):
            return self.strategies[strategy_name]
        raise Exception("Segment allocation strategy %s not found."
                        % (strategy_name))

REGISTRY = SegmentAllocationRegistry()
