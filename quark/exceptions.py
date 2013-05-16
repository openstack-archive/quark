from quantum.common import exceptions


class InvalidMacAddressRange(exceptions.QuantumException):
    message = _("Invalid MAC address range %(cidr)s.")


class MacAddressRangeNotFound(exceptions.NotFound):
    message = _("MAC address range %(mac_address_range_id) not found.")


class MacAddressRangeInUse(exceptions.InUse):
    message = _("MAC address range %(mac_address_range_id) in use.")


class RouteNotFound(exceptions.NotFound):
    message = _("Route %(route_id)s not found.")


class AmbiguousNetworkId(exceptions.QuantumException):
    message = _("Segment ID required for network %(net_id)s.")


class AmbigiousLswitchCount(exceptions.QuantumException):
    message = _("Too many lswitches for network %(net_id)s.")


class IpAddressNotFound(exceptions.QuantumException):
    message = _("IP Address %(addr_id)s not found.")


class RouteConflict(exceptions.QuantumException):
    message = _("Route overlaps existing route %(route_id)s with %(cidr)s")
