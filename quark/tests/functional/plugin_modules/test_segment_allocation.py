# Copyright 2013 Rackspace Hosting Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for# the specific language governing permissions and limitations
#  under the License.

from neutron_lib import exceptions as n_exc

from quark.db import api as db_api
from quark import exceptions as q_exc
import quark.plugin_modules.segment_allocation_ranges as sa_ranges_api
from quark import segment_allocations
from quark.tests.functional.base import BaseFunctionalTest


class QuarkSegmentAllocationTest(BaseFunctionalTest):

    def setUp(self):
        super(QuarkSegmentAllocationTest, self).setUp()
        self.segment_type = 'vxlan'
        self.segment_id = 'segment_id'
        self.old_context = self.context
        self.context = self.context.elevated()

    def _make_segment_allocation_range_dict(self, segment_type=None,
                                            segment_id=None,
                                            first_id=1,
                                            last_id=5):
        if not segment_type:
            segment_type = self.segment_type

        if not segment_id:
            segment_id = self.segment_id

        return {
            'segment_type': segment_type,
            'segment_id': segment_id,
            'first_id': first_id,
            'last_id': last_id,
        }

    def _populate_segment_allocation_range(self, sa_range):
        """Populate a given segment range."""

        # Range of ids to allocate, first to last (inclusive)
        id_range = xrange(sa_range['first_id'],
                          sa_range['last_id'] + 1)

        sa_dicts = []
        total = 0
        for i in id_range:
            sa_dicts.append({
                'segment_id': sa_range['segment_id'],
                'segment_type': sa_range['segment_type'],
                'id': i,
                'segment_allocation_range_id': sa_range['id'],
                'deallocated': True
            })
            total = total + 1
        db_api.segment_allocation_range_populate_bulk(self.context, sa_dicts)
        self.context.session.flush()

        # assert our allocation were actually created
        allocs = db_api.segment_allocation_find(
            self.context, segment_allocation_range_id=sa_range['id']).all()
        self.assertEqual(len(allocs), len(id_range))

    def _create_segment_allocation_range(self, **kwargs):
        """Create a segment allocation range in the database."""
        sa_dict = self._make_segment_allocation_range_dict(**kwargs)
        sa_range = db_api.segment_allocation_range_create(
            self.context, **sa_dict)
        self.context.session.flush()
        self._populate_segment_allocation_range(sa_range)
        return sa_range

    def _allocate_segment(self, sa_range, count=1):
        """Populate a given segment range."""
        allocs = []
        for i in xrange(sa_range['first_id'], sa_range['first_id'] + count):
            filters = {
                'segment_allocation_range_id': sa_range['id'],
                'deallocated': True
            }
            alloc = db_api.segment_allocation_find(
                self.context, **filters).first()
            if not alloc:
                raise Exception("Could not find deallocated id.")
            update = {
                'deallocated': False
            }
            allocs.append(
                db_api.segment_allocation_update(
                    self.context, alloc, **update)
            )
            self.context.session.flush()
        self.assertEqual(len(allocs), count)
        return allocs

    def _sa_range_to_dict(self, sa_range, allocations=None):
        """Helper to turn a model into a dict for assertions."""
        size = (sa_range['last_id'] + 1) - sa_range['first_id']
        sa_range_dict = dict(sa_range)
        sa_range_dict.pop('created_at')
        sa_range_dict['size'] = size

        if allocations is not None:
            sa_range_dict['free_ids'] = size - allocations
        return sa_range_dict


class QuarkTestVXLANSegmentAllocation(QuarkSegmentAllocationTest):

    def setUp(self):
        super(QuarkTestVXLANSegmentAllocation, self).setUp()
        self.registry = segment_allocations.SegmentAllocationRegistry()
        self.driver = self.registry.get_strategy('vxlan')

    def test_segment_allocation(self):
        sa_range = self._create_segment_allocation_range()

        # assert we allocate and update correctly
        alloc = self.driver.allocate(
            self.context, sa_range['segment_id'], 'network_id_1')
        self.assertEqual(alloc['segment_type'], sa_range['segment_type'])
        self.assertEqual(alloc['segment_id'], sa_range['segment_id'])
        self.assertEqual(alloc['network_id'], 'network_id_1')

        # assert the remaining allocations remain unallocated
        allocs = db_api.segment_allocation_find(
            self.context).all()
        allocs.remove(alloc)
        self.assertEqual(len(allocs), 4)
        self.assertTrue(all([a["deallocated"] for a in allocs]))

        return sa_range, alloc

    def test_segment_deallocation(self):
        # We call the allocate test to set up an initial allocation
        # and assert that it actually worked.
        sa_range, alloc = self.test_segment_allocation()

        self.driver.deallocate(
            self.context, sa_range['segment_id'], 'network_id_1')

        # assert that our previous allocation is now free
        allocs = db_api.segment_allocation_find(
            self.context, id=alloc['id'],
            segment_id=sa_range['segment_id']).all()

        self.assertEqual(len(allocs), 1)
        self.assertTrue(allocs[0]["deallocated"])
        self.assertEqual(allocs[0]["network_id"], None)

    def test_allocation_segment_full(self):
        # create a range, and allocate everything
        sa_range = self._create_segment_allocation_range()
        self._allocate_segment(sa_range, count=5)

        self.assertRaises(
            q_exc.SegmentAllocationFailure,
            self.driver.allocate,
            self.context, sa_range['segment_id'], 'network_id_2')


class QuarkTestCreateSegmentAllocationRange(QuarkSegmentAllocationTest):

    def test_create_segment_allocation_range_unauthorized(self):
        sa_range_dict = self._make_segment_allocation_range_dict()
        sa_range_request = {"segment_allocation_range": sa_range_dict}

        self.assertRaises(
            n_exc.NotAuthorized,
            sa_ranges_api.create_segment_allocation_range,
            self.old_context, sa_range_request)

    def test_create_segment_allocation_range(self):
        """Assert a range is created."""

        # Create a segment allocation range
        sa_range_dict = self._make_segment_allocation_range_dict()
        sa_range_request = {"segment_allocation_range": sa_range_dict}
        sa_range = sa_ranges_api.create_segment_allocation_range(
            self.context, sa_range_request)

        # Find all ranges added in the db
        sa_range_models = db_api.segment_allocation_range_find(
            self.context, scope=db_api.ALL)
        # ensure non-admins can fetch them as well
        sa_range_models = db_api.segment_allocation_range_find(
            self.old_context, scope=db_api.ALL)

        # Assert we actually added the range to the db with correct
        # values and returned the correct response.
        self.assertEqual(len(sa_range_models), 1)
        self.assertEqual(self._sa_range_to_dict(sa_range_models[0]),
                         sa_range)

    def test_create_segment_allocation_range_invalid_fails(self):
        """Assert segments with invalid ranges are disallowed."""
        sa_range_dict = self._make_segment_allocation_range_dict()
        sa_range_request = {"segment_allocation_range": sa_range_dict}

        invalid_ranges = [
            (0, 5),  # first_id < MIN,
            (1, 2 ** 24 + 1),  # last_id > MAX,
            (5, 1),  # last_id < first_id,
            ('a', 5),  # invalid data
        ]
        for first_id, last_id in invalid_ranges:
            sa_range_dict['first_id'] = first_id
            sa_range_dict['last_id'] = last_id
            self.assertRaises(
                q_exc.InvalidSegmentAllocationRange,
                sa_ranges_api.create_segment_allocation_range,
                self.context, sa_range_request)

    def test_create_segment_allocation_range_creates_allocations(self):
        """Assert created segments populate the allocation table."""
        sa_range_dict = self._make_segment_allocation_range_dict()
        sa_range_request = {"segment_allocation_range": sa_range_dict}
        sa_range = sa_ranges_api.create_segment_allocation_range(
            self.context, sa_range_request)

        allocs = db_api.segment_allocation_find(
            self.context, segment_allocation_range_id=sa_range['id']).all()
        self.assertEqual(len(allocs), sa_range['size'])

    def test_create_segment_allocation_ranges(self):
        """Assert segments with same type/id are allowed."""
        sa_range_dict = self._make_segment_allocation_range_dict()
        sa_range_request = {"segment_allocation_range": sa_range_dict}

        valid_ranges = [
            (10, 15),
            (5, 9),
            (16, 20),
        ]
        for first_id, last_id in valid_ranges:
            sa_range_dict['first_id'] = first_id
            sa_range_dict['last_id'] = last_id
            sa_range = sa_ranges_api.create_segment_allocation_range(
                self.context, sa_range_request)

            # Find all ranges added in the db
            sa_range_models = db_api.segment_allocation_range_find(
                self.context, id=sa_range['id'], scope=db_api.ALL)

            # Assert we actually added the range to the db with correct
            # values and returned the correct response.
            self.assertEqual(len(sa_range_models), 1)
            self.assertEqual(self._sa_range_to_dict(sa_range_models[0]),
                             sa_range)

    def test_create_segment_allocation_ranges_diff_overlap_allowed(self):
        """Assert different segments with overlapping ids are allowed."""
        sa_range_dict = self._make_segment_allocation_range_dict()
        sa_range_request = {"segment_allocation_range": sa_range_dict}

        segment_ids = [
            'segment1',
            'segment2',
            'segment3'
        ]
        for segment_id in segment_ids:
            sa_range_dict['first_id'] = 1
            sa_range_dict['last_id'] = 5
            sa_range_dict['segment_id'] = segment_id
            sa_range = sa_ranges_api.create_segment_allocation_range(
                self.context, sa_range_request)

            # Find all ranges added in the db
            sa_range_models = db_api.segment_allocation_range_find(
                self.context, id=sa_range['id'], scope=db_api.ALL)

            # Assert we actually added the range to the db with correct
            # values and returned the correct response.
            self.assertEqual(len(sa_range_models), 1)
            self.assertEqual(self._sa_range_to_dict(sa_range_models[0]),
                             sa_range)

    def test_create_segment_allocation_ranges_same_overlap_fails(self):
        """Assert same segments with overlapping ids are disallowed."""
        sa_range_dict = self._make_segment_allocation_range_dict()
        sa_range_request = {"segment_allocation_range": sa_range_dict}

        # create initial segment with range 10-15
        sa_range_dict['first_id'] = 10
        sa_range_dict['last_id'] = 15
        sa_ranges_api.create_segment_allocation_range(
            self.context, sa_range_request)

        invalid_ranges = [
            (10, 15),  # same range
            (5, 10),  # collides at start
            (15, 20),  # collides at end
            (8, 12),  # overlaps from start
            (12, 17),  # overlaps from end
            (9, 16),  # superset
            (11, 14)  # subset
        ]
        for first_id, last_id in invalid_ranges:
            sa_range_dict['first_id'] = first_id
            sa_range_dict['last_id'] = last_id
            self.assertRaises(
                q_exc.InvalidSegmentAllocationRange,
                sa_ranges_api.create_segment_allocation_range,
                self.context, sa_range_request)


class QuarkTestGetSegmentAllocationRange(QuarkSegmentAllocationTest):

    def test_get_segment_allocation_range_unauthorized(self):
        sa_range = self._create_segment_allocation_range()

        self.assertRaises(
            n_exc.NotAuthorized,
            sa_ranges_api.get_segment_allocation_range,
            self.old_context, sa_range["id"])

    def test_get_segment_allocation_range_not_found(self):
        self._create_segment_allocation_range()

        self.assertRaises(
            n_exc.NotFound,
            sa_ranges_api.get_segment_allocation_range,
            self.context, "some_id")

    def test_get_segment_allocation_range(self):
        sa_range = self._create_segment_allocation_range()

        result = sa_ranges_api.get_segment_allocation_range(
            self.context, sa_range['id'])

        expected_result = self._sa_range_to_dict(sa_range, allocations=0)
        self.assertEqual(expected_result, result)

    def test_get_segment_allocation_range_with_allocations(self):
        sa_range = self._create_segment_allocation_range()
        allocs = self._allocate_segment(sa_range, count=2)

        result = sa_ranges_api.get_segment_allocation_range(
            self.context, sa_range['id'])

        expected_result = self._sa_range_to_dict(
            sa_range, allocations=len(allocs))
        self.assertEqual(expected_result, result)


class QuarkTestGetSegmentAllocationRanges(QuarkSegmentAllocationTest):

    def test_get_segment_allocation_ranges_unauthorized(self):
        self.assertRaises(
            n_exc.NotAuthorized,
            sa_ranges_api.get_segment_allocation_ranges,
            self.old_context)

    def test_get_segment_allocation_ranges_empty(self):
        result = sa_ranges_api.get_segment_allocation_ranges(self.context)
        self.assertEqual([], result)

    def test_get_segment_allocation_ranges(self):
        sa_range = self._create_segment_allocation_range()
        sa_range2 = self._create_segment_allocation_range(
            first_id=6, last_id=10)

        result = sa_ranges_api.get_segment_allocation_ranges(self.context)

        ex_result = [self._sa_range_to_dict(r) for r in [sa_range, sa_range2]]
        self.assertEqual(ex_result, result)


class QuarkTestDeleteSegmentAllocationRange(QuarkSegmentAllocationTest):

    def test_delete_segment_allocation_range_not_found(self):
        self._create_segment_allocation_range()

        self.assertRaises(
            n_exc.NotFound,
            sa_ranges_api.delete_segment_allocation_range,
            self.context, "some_id")

    def test_delete_segment_allocation_range_unauthorized(self):
        sa_range = self._create_segment_allocation_range()

        # assert non-admins are not authorized
        self.assertRaises(
            n_exc.NotAuthorized,
            sa_ranges_api.delete_segment_allocation_range,
            self.old_context, sa_range["id"])

        # assert the range was not deleted
        sa_ranges = db_api.segment_allocation_range_find(
            self.context, id=sa_range["id"], scope=db_api.ALL)
        self.assertEqual(sa_ranges, [sa_range])

    def test_delete_segment_allocation_range_in_use_fails(self):
        sa_range = self._create_segment_allocation_range()
        self._allocate_segment(sa_range, count=1)

        self.assertRaises(
            n_exc.InUse,
            sa_ranges_api.delete_segment_allocation_range,
            self.context, sa_range["id"])

        # assert the range was not deleted
        sa_ranges = db_api.segment_allocation_range_find(
            self.context, id=sa_range["id"], scope=db_api.ALL)
        self.assertEqual(sa_ranges, [sa_range])

    def test_delete_segment_allocation_range_deletes(self):
        sa_range = self._create_segment_allocation_range()
        sa_range_id = sa_range["id"]

        sa_ranges_api.delete_segment_allocation_range(
            self.context, sa_range_id)

        # assert that the range and it's unused allocations are deleted
        sa_range = db_api.segment_allocation_range_find(
            self.context, id=sa_range_id, scope=db_api.ALL)
        allocs = db_api.segment_allocation_find(
            self.context, segment_allocation_range_id=sa_range_id).all()
        self.assertEqual(sa_range, [])
        self.assertEqual(allocs, [])
