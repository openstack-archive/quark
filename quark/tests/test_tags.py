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

from neutron_lib import exceptions as n_exc

from quark.db import models
from quark import tags
from quark.tests import test_base


class FakeTag(tags.Tag):

    NAME = "fake_tag"

    def validate(self, value):
        if value == "invalid":
            raise tags.TagValidationError(value, "FakeTag value is 'invalid'.")
        return True


class FooTag(tags.Tag):

    NAME = "foo_tag"

    def validate(self, value):
        if value != "foo":
            raise tags.TagValidationError(value, "FooTag value is not 'foo'.")
        return True


class FakeTagRegistry(tags.PortTagRegistry):
    def __init__(self, tags=None):
        if tags:
            self.tags = tags


class TestTagBase(test_base.TestBase):

    def setUp(self, tag=None, value=None, value2=None, invalid_value=None):
        super(TestTagBase, self).setUp()
        self.tag = tag if tag else FakeTag()
        self.value = value if value else "first"
        self.value2 = value2 if value2 else "second"
        self.invalid_value = invalid_value if invalid_value else "invalid"

        self.foo_tag = FooTag()
        self.existing_tags = ["EXISTING_TAG:already exists",
                              "random tag",
                              "123"]
        tags = {
            self.tag.get_name(): self.tag,
            self.foo_tag.get_name(): self.foo_tag
        }
        self.registry = FakeTagRegistry(tags=tags)

    def _create_test_model(self, id, tags=None):
        tags = tags if tags else []
        tags = self.existing_tags + tags
        model = models.Port(id=id, network_id="1", ip_addresses=[],
                            tags=tags)
        return model

    def _assert_tags(self, model, tags=None):
        """Assert given tags and already existing tags are present."""
        tags = tags if tags else []
        expected_tags = (self.existing_tags + tags)
        self.assertEqual(sorted(model.tags),
                         sorted(expected_tags))

    def test_tag_registry_get_all(self):
        model = self._create_test_model(1, tags=[])
        self.tag.set(model, self.value)
        self.foo_tag.set(model, "foo")
        expected_tags = [
            self.tag.serialize(self.value),
            self.foo_tag.serialize("foo")
        ]
        self._assert_tags(model, tags=expected_tags)

        tags = self.registry.get_all(model)
        self.assertEqual(tags, {self.tag.get_name(): str(self.value),
                                'foo_tag': 'foo'})

    def test_tag_registry_set_all(self):
        model = self._create_test_model(1, tags=[])
        self._assert_tags(model, tags=[])

        kwargs = {self.foo_tag.get_name(): "foo",
                  self.tag.get_name(): self.value}
        self.registry.set_all(model, **kwargs)

        expected_tags = [
            self.tag.serialize(self.value),
            self.foo_tag.serialize("foo")
        ]
        self._assert_tags(model, tags=expected_tags)

    def test_tag_registry_set_all_invalid_raises(self):
        model = self._create_test_model(1, tags=[])
        self._assert_tags(model, tags=[])

        kwargs = {self.foo_tag.get_name(): "foo",
                  self.tag.get_name(): self.invalid_value}

        with self.assertRaises(n_exc.BadRequest):
            self.registry.set_all(model, **kwargs)

    def test_tag_get(self):
        tags = [
            self.tag.serialize(self.value)
        ]
        model = self._create_test_model(1, tags=tags)
        self._assert_tags(model, tags=tags)

        self.assertEqual(self.tag.get(model), str(self.value))
        self._assert_tags(model, tags=tags)

        self.assertEqual(self.tag.get(model), str(self.value))
        self._assert_tags(model, tags=tags)

    def test_tag_get_invalid(self):
        tags = [
            self.foo_tag.serialize(self.invalid_value)
        ]
        model = self._create_test_model(1, tags=tags)
        self._assert_tags(model, tags=tags)

        self.assertEqual(self.tag.get(model), None)
        self._assert_tags(model, tags=tags)

    def test_tag_set(self):
        model = self._create_test_model(1, tags=[])
        self._assert_tags(model, tags=[])

        expected_tags = [
            self.tag.serialize(self.value)
        ]

        self.tag.set(model, self.value)
        self._assert_tags(
            model, tags=expected_tags)

        self.tag.set(model, self.value)
        self._assert_tags(
            model, tags=expected_tags)

    def test_tag_set_existing(self):
        tags = [
            self.tag.serialize(self.value)
        ]
        model = self._create_test_model(1, tags=tags)
        self._assert_tags(model, tags=tags)

        self.tag.set(model, self.value2)
        self._assert_tags(
            model, tags=[self.tag.serialize(self.value2)])

    def test_tag_set_invalid(self):
        model = self._create_test_model(1, tags=[])

        with self.assertRaises(tags.TagValidationError):
            self.tag.set(model, self.invalid_value)

        self._assert_tags(model, tags=[])

    def test_pop(self):
        tags = [
            self.tag.serialize(self.value)
        ]
        model = self._create_test_model(1, tags=tags)
        self._assert_tags(model, tags=tags)

        self.assertEqual(self.tag.pop(model), str(self.value))
        self._assert_tags(model, tags=[])

        self.assertEqual(self.tag.pop(model), None)
        self._assert_tags(model, tags=[])

    def test_pop_invalid(self):
        tags = [
            self.tag.serialize(self.invalid_value),
            self.tag.serialize(self.value),
            self.tag.serialize(self.value2)
        ]
        model = self._create_test_model(1, tags=tags)
        self._assert_tags(model, tags=tags)

        self.assertTrue(self.tag.pop(model) in
                        [str(self.value), str(self.value2)])
        self._assert_tags(model, tags=[])

        self.assertEqual(self.tag.pop(model), None)
        self._assert_tags(model, tags=[])


class TestVlanTag(TestTagBase):

    def setUp(self):
        tag = tags.VlanTag()
        value = 50
        value2 = 100
        invalid_value = 5000
        super(TestVlanTag, self).setUp(
            tag=tag, value=value, value2=value2, invalid_value=invalid_value)

    def test_vlan_validation(self):
        model = self._create_test_model(1, tags=[])

        with self.assertRaises(tags.TagValidationError):
            self.tag.set(model, self.tag.MIN_VLAN_ID - 1)
        self._assert_tags(model, tags=[])

        with self.assertRaises(tags.TagValidationError):
            self.tag.set(model, self.tag.MAX_VLAN_ID + 1)
        self._assert_tags(model, tags=[])

        with self.assertRaises(tags.TagValidationError):
            self.tag.set(model, 'three')
        self._assert_tags(model, tags=[])

        self.tag.set(model, self.tag.MIN_VLAN_ID)
        self._assert_tags(
            model, tags=[self.tag.serialize(self.tag.MIN_VLAN_ID)])

        self.tag.set(model, self.tag.MAX_VLAN_ID)
        self._assert_tags(
            model, tags=[self.tag.serialize(self.tag.MAX_VLAN_ID)])

        self.tag.set(model, str(self.tag.MIN_VLAN_ID))
        self._assert_tags(
            model, tags=[self.tag.serialize(self.tag.MIN_VLAN_ID)])

        self.tag.set(model, str(self.tag.MAX_VLAN_ID))
        self._assert_tags(
            model, tags=[self.tag.serialize(self.tag.MAX_VLAN_ID)])
