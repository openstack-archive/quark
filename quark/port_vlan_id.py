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

VLAN_TAG_PREFIX = "VLAN_ID:"
MIN_VLAN_ID = 1
MAX_VLAN_ID = 4096


class InvalidVlanIdError(Exception):
    """Raised if an invalid VLAN ID is detected."""
    def __init__(self, vlan_id):
        self.vlan_id = vlan_id
        self.message = ("Invalid VLAN ID detected. Got '%(vlan_id)s'. "
                        "Integer conversion yields: '%(vlan_id_int)d'. "
                        "VLAN ID should be between %(min)d and %(max)d "
                        "inclusive." % {'vlan_id': vlan_id,
                                        'vlan_id_int': int(vlan_id),
                                        'min': MIN_VLAN_ID,
                                        'max': MAX_VLAN_ID})


def _validate_vlan_id(vlan_id):
    """Validates a VLAN ID.

    :param vlan_id: The VLAN ID to validate against.
    :raises InvalidVlanIdError: Raised if the VLAN ID is invalid.
    """
    vlan_id_int = int(vlan_id)
    if vlan_id_int < MIN_VLAN_ID or vlan_id_int > MAX_VLAN_ID:
        raise InvalidVlanIdError(vlan_id)


def _build_vlan_tag_string(vlan_id):
    """Builds a VLAN ID tag string.

    :param vlan_id: The VLAN ID as a string.
    :returns: The VLAN ID string as appropriate for a port tag.
    """
    return "%s%d" % (VLAN_TAG_PREFIX, int(vlan_id))


def store_vlan_id(port, vlan_id):
    """Stores a VLAN ID on a specified port.

    :param port: The port object on which to store the VLAN ID.
    :param vlan_id: The VLAN ID as a string.

    :raises InvalidVlanIdError: If the vlan_id is invalid, this exception
        is raised.
    """
    _validate_vlan_id(vlan_id)
    port.tags.append(_build_vlan_tag_string(vlan_id))


def retrieve_vlan_id(port):
    """Retrieves the VLAN ID associated with the given port, if it exists.

    :param port: The port object.
    :returns: The VLAN ID as an integer, if the port has one attached.
        Otherwise returns None.

    :raises InvalidVlanIdError: This exception is raised if the retrieved
        VLAN ID is invalid.
    """
    for tag in port.tags:
        if is_vlan_id_tag(tag):
            vlan_id = _extract_vlan_id_from_tag(tag)
            _validate_vlan_id(vlan_id)
            return vlan_id

    return None


def _extract_vlan_id_from_tag(tag):
    """Extracts the VLAN ID from a given tag, if possible.

    Assumes the tag argument is definitely a VLAN ID tag as identified by
    is_vlan_id_tag(tag).

    :param tag: The tag object.
    :returns: The VLAN ID as an integer if extraction is successful
       Otherwise returns None.
    """
    try:
        vlan_id = int(tag[len(VLAN_TAG_PREFIX):])
    except Exception:
        return None
    return vlan_id


def is_vlan_id_tag(tag):
    """Determines if the given tag is a VLAN tag.

    :param tag: A tag model object.
    :returns: True if the tag is a VLAN ID tag. False otherwise.
    """
    return tag[0:len(VLAN_TAG_PREFIX)] == VLAN_TAG_PREFIX


def has_vlan_id(port):
    """Determines if the specified port has a VLAN ID attached.

    :param port: The port object.
    :returns: True if the port has an associated VLAN ID, False otherwise.
    """
    for tag in port.tags:
        if is_vlan_id_tag(tag):
            return True
    return False
