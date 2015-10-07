# Copyright 2015 Rackspace
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

import random
import string

from quark.db import models
from quark import port_vlan_id
from quark.tests import test_base

MAX_VLAN_ID = port_vlan_id.MAX_VLAN_ID
MIN_VLAN_ID = port_vlan_id.MIN_VLAN_ID


class TestPortVlanId(test_base.TestBase):
    def setUp(self):
        super(TestPortVlanId, self).setUp()
        self.port_with_vlan = (
            self._create_port_with_vlan_id(
                0, random.randrange(MIN_VLAN_ID, MAX_VLAN_ID)))
        self.port_without_vlan = self._create_test_port(1)

    def _create_test_port_with_lots_of_tags(self, port_id, vlan_id):
        port = self._create_test_port(port_id)
        port.tags.append("One weird olde tag.")
        port.tags.append("Yet another tag.")
        if vlan_id is not None:
            port_vlan_id.store_vlan_id(port, vlan_id)
        port.tags.append("One final tag")
        return port

    def _create_test_port(self, port_id):
        port = models.Port(id=port_id, network_id="1", ip_addresses=[],
                           tags=[])
        return port

    def _create_port_with_vlan_id(self, port_id, vlan_id):
        port = self._create_test_port(port_id)
        tag_contents = "%s%d" % (port_vlan_id.VLAN_TAG_PREFIX, vlan_id)
        port.tags.append(tag_contents)
        return port

    def test__validate_vlan_id(self):
        valid_ids = [MIN_VLAN_ID, MAX_VLAN_ID]
        for n in range(0, 10):
            valid_ids.append(random.randrange(MIN_VLAN_ID, MAX_VLAN_ID))
        for vlan_id in valid_ids:
            try:
                port_vlan_id._validate_vlan_id(vlan_id)
            except port_vlan_id.InvalidVlanIdError as e:
                self.assertFalse(True,
                                 "_validate_vlan_id raised an exception on "
                                 "what should be a valid VLAN ID. Exception "
                                 "message: %s" % (e.message))

        invalid_ids = [MIN_VLAN_ID - 1, MAX_VLAN_ID + 1]
        for n in range(0, 5):
            valid_ids.append(random.randrange(MAX_VLAN_ID + 1,
                                              MAX_VLAN_ID + 100))
            valid_ids.append(random.randrange(MIN_VLAN_ID - 100,
                                              MIN_VLAN_ID - 1))
        for vlan_id in invalid_ids:
            # _validate_vlan_id should raise on invalid IDs.
            self.assertRaises(port_vlan_id.InvalidVlanIdError,
                              port_vlan_id._validate_vlan_id,
                              vlan_id)

    def test_store_vlan_id_vlan(self):
        # Test against a valid VLAN ID
        port = self.port_without_vlan
        port_vlan_id.store_vlan_id(port, MIN_VLAN_ID)
        self.assertTrue(len(port.tags) == 1)
        vlan_tag = port.tags[0]
        self.assertTrue(string.find(vlan_tag,
                                    port_vlan_id.VLAN_TAG_PREFIX) == 0,
                        "Couldn't find the VLAN tag prefix in the vlan tag!")
        self.assertTrue(string.find(vlan_tag, str(MIN_VLAN_ID)) != -1,
                        "The VLAN ID was not stored in the VLAN tag!")

        # Also test against an invalid ID
        self.port_without_vlan = self._create_test_port(2)
        port = self.port_without_vlan
        self.assertRaises(port_vlan_id.InvalidVlanIdError,
                          port_vlan_id.store_vlan_id,
                          port, port_vlan_id.MIN_VLAN_ID - 1)
        self.assertTrue(len(port.tags) == 0,
                        "The port has a new tag, even though the VLAN ID was "
                        "invalid!")

    def test_retrieve_vlan_id(self):
        # VLAN ID exists
        port = self.port_with_vlan
        vlan_id = port_vlan_id.retrieve_vlan_id(port)
        self.assertIsNotNone(vlan_id,
                             "VLAN ID returned by retrieve_vlan_id "
                             "is None despite having stored the VLAN ID on "
                             "this port earlier.")

        # VLAN ID is absent
        port = self.port_without_vlan
        vlan_id = port_vlan_id.retrieve_vlan_id(port)
        self.assertIsNone(vlan_id,
                          "VLAN ID is not None, even though the port does "
                          "not have a VLAN ID stored.")

        # Other tags are present on the port.
        port = self._create_test_port_with_lots_of_tags(3, 5)
        vlan_id = port_vlan_id.retrieve_vlan_id(port)
        self.assertEqual(5, vlan_id,
                         "Retrieved VLAN ID did not match expectations with "
                         "another tag present.")

    def test_is_vlan_id_tag(self):
        # Test some good cases, note that is_vlan_id_tag doesn't validate
        # the VLAN_ID itself, as it should've been validated before it was
        # stored to the port model.
        test_ids = [-1, 2, 3, 4, 100, 1000, 5234, "puppy", "dog"]
        good_tags = [("%s%s" % (port_vlan_id.VLAN_TAG_PREFIX, vlan_id))
                     for vlan_id in str(test_ids)]
        for tag in good_tags:
            self.assertTrue(port_vlan_id.is_vlan_id_tag(tag),
                            "A known good tag was not recognized as one by "
                            "is_vlan_id_tag. Tag: '%(tag)s'" % {'tag': tag})

        # Test some bad ones
        bad_tags = ["", "snake:50", "cipher", "zero", "[]asdrf897y",
                    port_vlan_id.VLAN_TAG_PREFIX[:-2],
                    "some_other_key_value_pair:234"]
        for tag in bad_tags:
            self.assertFalse(port_vlan_id.is_vlan_id_tag(tag),
                             "A known bad tag was recognized as a VLAN ID tag "
                             "by is_vlan_id_tag. Tag: '%(tag)s'" %
                             {'tag': tag})

    def test_has_vlan_id(self):
        # Test port with VLAN ID, but no other tags
        port = self.port_with_vlan
        self.assertTrue(port_vlan_id.has_vlan_id(port),
                        "has_vlan_id returned False even though the port is "
                        "known to have a valid VLAN ID tag.")

        # Test port without, no tags
        port = self.port_without_vlan
        self.assertFalse(port_vlan_id.has_vlan_id(port),
                         "has_vlan_id returned True even though the port "
                         "doesn't have a VLAN ID tag.")

        # Test port with VLAN ID, and several tags
        port = self._create_test_port_with_lots_of_tags(5, 1337)
        self.assertTrue(port_vlan_id.has_vlan_id(port),
                        "has_vlan_id returned False even though the port "
                        "has a VLAN ID tag.")

        # Test port without VLAN ID, but with several tags
        port = self._create_test_port_with_lots_of_tags(5, None)
        self.assertFalse(port_vlan_id.has_vlan_id(port),
                         "has_vlan_id returned True even though the port "
                         "does not have a VLAN ID tag.")
