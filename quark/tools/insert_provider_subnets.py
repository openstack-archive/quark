import sys

from neutron.common import config
from neutron.db import api as neutron_db_api
from oslo_config import cfg
from oslo_db.exception import DBDuplicateEntry
from oslo_log import log as logging

from quark.db import models

LOG = logging.getLogger(__name__)


def main():
    config.init(sys.argv[1:])
    if not cfg.CONF.config_file:
        sys.exit(_("ERROR: Unable to find configuration file via the default"
                   " search paths (~/.neutron/, ~/, /etc/neutron/, /etc/) and"
                   " the '--config-file' option!"))

    config.setup_logging()
    session = neutron_db_api.get_session()
    subnets = [
        models.Subnet(name="public_v4",
                      network_id="00000000-0000-0000-0000-000000000000",
                      id="00000000-0000-0000-0000-000000000000",
                      tenant_id="rackspace",
                      segment_id="rackspace",
                      do_not_use=True,
                      _cidr="0.0.0.0/0"),
        models.Subnet(name="public_v6",
                      network_id="00000000-0000-0000-0000-000000000000",
                      id="11111111-1111-1111-1111-111111111111",
                      tenant_id="rackspace",
                      segment_id="rackspace",
                      do_not_use=True,
                      _cidr="::/0"),
        models.Subnet(name="private_v4",
                      network_id="11111111-1111-1111-1111-111111111111",
                      id="22222222-2222-2222-2222-222222222222",
                      tenant_id="rackspace",
                      segment_id="rackspace",
                      do_not_use=True,
                      _cidr="0.0.0.0/0"),
        models.Subnet(name="private_v6",
                      network_id="11111111-1111-1111-1111-111111111111",
                      id="33333333-3333-3333-3333-333333333333",
                      tenant_id="rackspace",
                      segment_id="rackspace",
                      do_not_use=True,
                      _cidr="::/0")]
    try:
        session.bulk_save_objects(subnets)
    except DBDuplicateEntry:
        LOG.warn("Provider subnets previously inserted into database")


if __name__ == "__main__":
    main()
