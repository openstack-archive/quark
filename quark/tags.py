# Copyright 2015 Rackspace Hosting Inc.
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


class TagValidationError(Exception):
    def __init__(self, value, message):
        self.value = value
        self.message = message


class Tag(object):

    @classmethod
    def get_name(cls):
        """API name of the tag."""
        if not hasattr(cls, 'NAME'):
            raise NotImplementedError()
        return cls.NAME

    @classmethod
    def get_prefix(cls):
        """Tag 'key', saved in the database as <prefix>:<value>"""
        return "%s:" % cls.get_name().upper()

    def serialize(self, value):
        return "%s%s" % (self.get_prefix(), value)

    def deserialize(self, tag):
        if self.is_tag(tag):
            try:
                return tag[len(self.get_prefix()):]
            except Exception:
                pass
        return None

    def validate(self, value):
        raise NotImplementedError

    def set(self, model, value):
        """Set tag on model object."""
        self.validate(value)
        self._pop(model)
        value = self.serialize(value)
        model.tags.append(value)

    def get(self, model):
        """Get a matching valid tag off the model."""
        for tag in model.tags:
            if self.is_tag(tag):
                value = self.deserialize(tag)
                try:
                    self.validate(value)
                    return value
                except TagValidationError:
                    continue
        return None

    def _pop(self, model):
        """Pop all matching tags off the model and return them."""
        tags = []

        # collect any exsiting tags with matching prefix
        for tag in model.tags:
            if self.is_tag(tag):
                tags.append(tag)

        # remove collected tags from model
        if tags:
            for tag in tags:
                model.tags.remove(tag)

        return tags

    def pop(self, model):
        """Pop all matching tags off the port, return a valid one."""
        tags = self._pop(model)
        if tags:
            for tag in tags:
                value = self.deserialize(tag)
                try:
                    self.validate(value)
                    return value
                except TagValidationError:
                    continue

    def is_tag(self, tag):
        """Is a given tag this type?"""
        return tag[0:len(self.get_prefix())] == self.get_prefix()

    def has_tag(self, model):
        """Does the given port have this tag?"""
        for tag in model.tags:
            if self.is_tag(tag):
                return True
        return False


class VlanTag(Tag):

    NAME = "vlan_id"
    MIN_VLAN_ID = 1
    MAX_VLAN_ID = 4096

    def validate(self, value):
        """Validates a VLAN ID.

        :param value: The VLAN ID to validate against.
        :raises TagValidationError: Raised if the VLAN ID is invalid.
        """
        try:
            vlan_id_int = int(value)
            assert vlan_id_int >= self.MIN_VLAN_ID
            assert vlan_id_int <= self.MAX_VLAN_ID
        except Exception:
            msg = ("Invalid vlan_id. Got '%(vlan_id)s'. "
                   "vlan_id should be an integer between %(min)d and %(max)d "
                   "inclusive." % {'vlan_id': value,
                                   'min': self.MIN_VLAN_ID,
                                   'max': self.MAX_VLAN_ID})
            raise TagValidationError(value, msg)
        return True


class TagRegistry(object):

    tags = {}

    def get_all(self, model):
        """Get all known tags from a model.

        Returns a dict of {<tag_name>:<tag_value>}.
        """
        tags = {}
        for name, tag in self.tags.items():
            for mtag in model.tags:
                if tag.is_tag(mtag):
                    tags[name] = tag.get(model)
        return tags

    def set_all(self, model, **tags):
        """Validate and set all known tags on a port."""
        for name, tag in self.tags.items():
            if name in tags:
                value = tags.pop(name)
                if value:
                    try:
                        tag.set(model, value)
                    except TagValidationError as e:
                        raise n_exc.BadRequest(
                            resource="tags",
                            msg="%s" % (e.message))


class PortTagRegistry(TagRegistry):

    def __init__(self):
        self.tags = {
            VlanTag.get_name(): VlanTag()
        }


PORT_TAG_REGISTRY = PortTagRegistry()
