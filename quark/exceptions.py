# Copyright 2016 Rackspace Hosting Inc.
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


class NetworkAlreadyExists(n_exc.Conflict):
    message = _("Network %(id)s already exists.")


class InvalidMacAddressRange(n_exc.NeutronException):
    message = _("Invalid MAC address range %(cidr)s.")


class InvalidEthertype(n_exc.NeutronException):
    message = _("Invalid Ethertype %(ethertype)s.")


class MacAddressRangeNotFound(n_exc.NotFound):
    message = _("MAC address range %(mac_address_range_id)s not found.")


class MacAddressRangeInUse(n_exc.InUse):
    message = _("MAC address range %(mac_address_range_id)s in use.")


class MacAddressNotFound(n_exc.NotFound):
    message = _("MAC address %(mac_address_id)s (%(readable_mac)s) not found.")


class InvalidSegmentAllocationRange(n_exc.NeutronException):
    message = _("Invalid segment allocation range: %(msg)s.")


class SegmentAllocationRangeNotFound(n_exc.NotFound):
    message = _(
        "Segment allocation range %(segment_allocation_range_id)s not found.")


class SegmentAllocationRangeInUse(n_exc.InUse):
    message = _(
        "Segment allocation range %(segment_allocation_range_id)s in use.")


class SegmentAllocationFailure(n_exc.Conflict):
    message = _("No more segment ids available for segment "
                "type:%(segment_type)s id:%(segment_id)s.")


class RouteNotFound(n_exc.NotFound):
    message = _("Route %(route_id)s not found.")


class AmbiguousNetworkId(n_exc.InvalidInput):
    msg = _("Segment ID required for network %(net_id)s.")


class AmbigiousLswitchCount(n_exc.NeutronException):
    message = _("Too many lswitches for network %(net_id)s.")


class IpAddressNotFound(n_exc.NotFound):
    message = _("IP Address %(addr_id)s not found.")


class PortRequiresDisassociation(n_exc.BadRequest):
    message = _("Port requires disassociation before IP can be deleted")


class RouteConflict(n_exc.NeutronException):
    message = _("Route overlaps existing route %(route_id)s with %(cidr)s")


class DuplicateRouteConflict(n_exc.NeutronException):
    message = _("More than one default route found for subnet %(subnet_id)s")


class InvalidPhysicalNetworkType(n_exc.NeutronException):
    message = _("Providernet type %(net_type)s is invalid")


class SegmentIdUnsupported(n_exc.NeutronException):
    message = _("Segmentation ID is unsupported for network type %(net_type)s")


class SegmentIdRequired(n_exc.NeutronException):
    message = _("Segmentation ID is required for network type %(net_type)s")


class PhysicalNetworkNotFound(n_exc.NeutronException):
    message = _("Physical network %(phys_net)s not found!")


class InvalidIpamStrategy(n_exc.BadRequest):
    message = _("IPAM Strategy %(strat)s is invalid.")


class ProvidernetParamError(n_exc.NeutronException):
    message = _("%(msg)s")


class BadNVPState(n_exc.NeutronException):
    message = _("No networking information found for network %(net_id)s")


class IPAddressRetryableFailure(n_exc.NeutronException):
    message = _("Allocation of %(ip_addr)s for net %(net_id)s failed, "
                "retrying...")


class IPAddressPolicyRetryableFailure(IPAddressRetryableFailure):
    message = _("Allocation of %(ip_addr)s for net %(net_id)s failed "
                "due to policy retrying...")


class IPAddressNotInSubnet(n_exc.InvalidInput):
    message = _("Requested IP %(ip_addr)s not in subnet %(subnet_id)s")


class IPAddressProhibitedByPolicy(n_exc.InvalidInput):
    message = _("IP %(ip_addr)s is prohibited by policies on the subnet")


class ProviderNetworkOutOfIps(n_exc.NeutronException):
    message = _("Network %(net_id)s appears to be out of IP Addresses."
                "You may want to try again in a few seconds")


class IPPolicyNotFound(n_exc.NeutronException):
    message = _("IP Policy %(id)s not found.")


class IPPolicyAlreadyExists(n_exc.NeutronException):
    message = _("IP Policy %(id)s already exists for %(n_id)s")


class IPPolicyInUse(n_exc.InUse):
    message = _("IP allocation policy %(id)s in use.")


class DriverLimitReached(n_exc.InvalidInput):
    message = _("Driver has reached limit on resource '%(limit)s'")


class SecurityGroupsNotImplemented(n_exc.InvalidInput):
    message = _("Security Groups are not currently implemented on port "
                "create")


class TenantNetworkSecurityGroupRulesNotEnabled(n_exc.InvalidInput):
    message = _("Tenant network security group rules are not currently "
                "allowed by environment_capabilities configuration.")


class EgressSecurityGroupRulesNotEnabled(n_exc.InvalidInput):
    message = _("Egress security group rules are not currently allowed "
                "by environment_capabilities configuration.")


class SecurityGroupsRequireDevice(n_exc.InvalidInput):
    message = _("Security Groups may only be applied to ports connected to "
                "devices")


class RedisConnectionFailure(n_exc.NeutronException):
    message = _("No connection to Redis could be made.")


class NoBackendConnectionsDefined(n_exc.NeutronException):
    message = _("This driver cannot be used without a backend connection "
                "definition. %(msg)s")


class FloatingIpNotFound(n_exc.NotFound):
    message = _("Floating IP %(id)s not found.")


class ScalingIpNotFound(n_exc.NotFound):
    message = _("Scaling IP %(id)s not found.")


class RemoveFloatingIpFailure(n_exc.NeutronException):
    message = _("An error occurred when trying to remove the "
                "floating IP %(id)s.")


class RegisterFloatingIpFailure(n_exc.NeutronException):
    message = _("An error occurred when trying to register the floating IP "
                "%(id)s.")


class PortAlreadyContainsFloatingIp(n_exc.Conflict):
    message = _("Port %(port_id)s already has an associated floating IP.")


class FixedIpDoesNotExistsForPort(n_exc.BadRequest):
    message = _("Fixed IP %(fixed_ip)s does not exist on Port %(port_id)s")


class PortAlreadyContainsScalingIp(n_exc.Conflict):
    message = _("Port %(port_id)s already has an associated scaling IP.")


class NoAvailableFixedIpsForPort(n_exc.Conflict):
    message = _("There are no available fixed IPs for port %(port_id)s")


class PortDoesNotHaveAGateway(n_exc.Conflict):
    message = _("Port %(port_id)s does not have a gateway")


class PortAlreadyAssociatedToFloatingIp(n_exc.BadRequest):
    message = _("Port %(port_id)s is already associated with "
                "floating IP %(flip_id)s")


class FloatingIpUpdateNoPortIdSupplied(n_exc.BadRequest):
    message = _("When no port is currently associated to the floating IP, "
                "port_id is required but was not supplied")


class PortOrDeviceNotFound(n_exc.PortNotFound):
    message = _("Suitable port or device could not be found")


class NotAllPortOrDeviceFound(n_exc.NotFound):
    message = _("Not all ports or devices from request could be found")


class CannotAddMoreIPsToPort(n_exc.OverQuota):
    message = _("Cannot add more IPs to port")


class CannotCreateMoreSharedIPs(n_exc.OverQuota):
    message = _("Cannot create more shared IPs on selected network")


class JobNotFound(n_exc.NotFound):
    message = _("Job %(job_id)s not found")
