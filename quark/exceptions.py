from quantum.common import exceptions


class InvalidMacAddressRange(exceptions.QuantumException):
    message = _("Invalid MAC address range %(cidr)s.")


class RouteNotFound(exceptions.NotFound):
    message = _("Route %(route_id)s not found.")


class AmbigiousLswitchCount(exceptions.QuantumException):
    message = _("Too many lswitches for network %(net_id)s.")


class IpAddressNotFound(exceptions.QuantumException):
    message = _("IP Address %(addr_id)s not found.")


class RouteConflict(exceptions.QuantumException):
    message = _("Route overlaps existing route %(route_id)s with %(cidr)s")
