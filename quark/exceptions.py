from neutron.common import exceptions


class NetworkAlreadyExists(exceptions.Conflict):
    message = _("Network %(id)s already exists.")


class InvalidMacAddressRange(exceptions.NeutronException):
    message = _("Invalid MAC address range %(cidr)s.")


class InvalidEthertype(exceptions.NeutronException):
    message = _("Invalid Ethertype %(ethertype)s.")


class MacAddressRangeNotFound(exceptions.NotFound):
    message = _("MAC address range %(mac_address_range_id) not found.")


class MacAddressRangeInUse(exceptions.InUse):
    message = _("MAC address range %(mac_address_range_id) in use.")


class RouteNotFound(exceptions.NotFound):
    message = _("Route %(route_id)s not found.")


class AmbiguousNetworkId(exceptions.InvalidInput):
    msg = _("Segment ID required for network %(net_id)s.")


class AmbigiousLswitchCount(exceptions.NeutronException):
    message = _("Too many lswitches for network %(net_id)s.")


class IpAddressNotFound(exceptions.NotFound):
    message = _("IP Address %(addr_id)s not found.")


class PortRequiresDisassociation(exceptions.BadRequest):
    message = _("Port requires disassociation before IP can be deleted")


class RouteConflict(exceptions.NeutronException):
    message = _("Route overlaps existing route %(route_id)s with %(cidr)s")


class DuplicateRouteConflict(exceptions.NeutronException):
    message = _("More than one default route found for subnet %(subnet_id)s")


class InvalidPhysicalNetworkType(exceptions.NeutronException):
    message = _("Providernet type %(net_type)s is invalid")


class SegmentIdUnsupported(exceptions.NeutronException):
    message = _("Segmentation ID is unsupported for network type %(net_type)s")


class SegmentIdRequired(exceptions.NeutronException):
    message = _("Segmentation ID is required for network type %(net_type)s")


class PhysicalNetworkNotFound(exceptions.NeutronException):
    message = _("Physical network %(phys_net)s not found!")


class InvalidIpamStrategy(exceptions.BadRequest):
    message = _("IPAM Strategy %(strat)s is invalid.")


class ProvidernetParamError(exceptions.NeutronException):
    message = _("%(msg)s")


class BadNVPState(exceptions.NeutronException):
    message = _("No networking information found for network %(net_id)s")


class IPAddressRetryableFailure(exceptions.NeutronException):
    message = _("Allocation of %(ip_addr)s for net %(net_id)s failed, "
                "retrying...")


class IPAddressPolicyRetryableFailure(IPAddressRetryableFailure):
    message = _("Allocation of %(ip_addr)s for net %(net_id)s failed "
                "due to policy retrying...")


class IPAddressNotInSubnet(exceptions.InvalidInput):
    message = _("Requested IP %(ip_addr)s not in subnet %(subnet_id)s")


class IPAddressProhibitedByPolicy(exceptions.InvalidInput):
    message = _("IP %(ip_addr)s is prohibited by policies on the subnet")


class IPPolicyNotFound(exceptions.NeutronException):
    message = _("IP Policy %(id)s not found.")


class IPPolicyAlreadyExists(exceptions.NeutronException):
    message = _("IP Policy %(id)s already exists for %(n_id)s")


class IPPolicyInUse(exceptions.InUse):
    message = _("IP allocation policy %(id) in use.")


class DriverLimitReached(exceptions.InvalidInput):
    message = _("Driver has reached limit on resource '%(limit)s'")


class SecurityGroupsNotImplemented(exceptions.InvalidInput):
    message = _("Security Groups are not currently implemented on port "
                "create")


class TenantNetworkSecurityGroupsNotImplemented(exceptions.InvalidInput):
    message = _("Security Groups are not currently implemented for "
                "tenant networks")


class SecurityGroupsRequireDevice(exceptions.InvalidInput):
    message = _("Security Groups may only be applied to ports connected to "
                "devices")


class RedisConnectionFailure(exceptions.NeutronException):
    message = _("No connection to Redis could be made.")


class NoBackendConnectionsDefined(exceptions.NeutronException):
    message = _("This driver cannot be used without a backend connection "
                "definition. %(msg)")


class FloatingIpNotFound(exceptions.NeutronException):
    message = _("Floating IP %(id)s not found.")


class RemoveFloatingIpFailure(exceptions.NeutronException):
    message = _("An error occurred when trying to remove the "
                "floating IP %(id).")


class RegisterFloatingIpFailure(exceptions.NeutronException):
    message = _("An error occurred when trying to register the floating IP "
                "%(id).")


class PortAlreadyContainsFloatingIp(exceptions.Conflict):
    message = _("Port %(port_id) already has an associated floating IP.")


class FixedIpDoesNotExistsForPort(exceptions.BadRequest):
    message = _("Fixed IP %(fixed_ip) does not exist on Port %(port_id)")


class NoAvailableFixedIPsForPort(exceptions.Conflict):
    message = _("There are no available fixed IPs for port %(port_id)")


class PortDoesNotHaveAGateway(exceptions.Conflict):
    message = _("Port %(port_id) does not have a gateway")


class PortAlreadyAssociatedToFloatingIP(exceptions.BadRequest):
    message = _("Port %(port_id) is already associated with "
                "floating IP %(flip_id)")


class FloatingIPUpdateNoPortIdSupplied(exceptions.BadRequest):
    message = _("When no port is currently associated to the floating IP, "
                "port_id is required but was not supplied")


class PortOrDeviceNotFound(exceptions.PortNotFound):
    message = _("Suitable port or device could not be found")


class NotAllPortOrDeviceFound(exceptions.NotFound):
    message = _("Not all ports or devices from request could be found")


class CannotAddMoreIPsToPort(exceptions.OverQuota):
    message = _("Cannot add more IPs to port")


class CannotCreateMoreSharedIPs(exceptions.OverQuota):
    message = _("Cannot create more shared IPs on selected network")
