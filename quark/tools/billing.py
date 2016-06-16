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

"""Calculations for different cases for additional IP billing
See notes in quark/billing.py for more details.
"""

import click
import datetime

from neutron.common import config
from neutron import context as neutron_context

from pprint import pprint as pp
from quark import billing
from quark.db import models
from quark import network_strategy


def make_case2(context):
    """This is a helper method for testing.

    When run with the current context, it will create a case 2 entries
    in the database. See top of file for what case 2 is.
    """
    query = context.session.query(models.IPAddress)
    period_start, period_end = billing.calc_periods()
    ip_list = billing.build_full_day_ips(query, period_start, period_end)
    import random
    ind = random.randint(0, len(ip_list) - 1)
    address = ip_list[ind]
    address.allocated_at = datetime.datetime.utcnow() -\
        datetime.timedelta(days=1)
    context.session.add(address)
    context.session.flush()


@click.command()
@click.option('--notify', is_flag=True,
              help='If true, sends notifications to billing')
@click.option('--hour', default=0,
              help='period start hour, e.g. 0 is midnight')
@click.option('--minute', default=0,
              help='period start minute, e.g. 0 is top of the hour')
def main(notify, hour, minute):
    """Runs billing report. Optionally sends notifications to billing"""

    # Read the config file and get the admin context
    config_opts = ['--config-file', '/etc/neutron/neutron.conf']
    config.init(config_opts)
    # Have to load the billing module _after_ config is parsed so
    # that we get the right network strategy
    network_strategy.STRATEGY.load()
    billing.PUBLIC_NETWORK_ID = network_strategy.STRATEGY.get_public_net_id()
    config.setup_logging()
    context = neutron_context.get_admin_context()

    # A query to get all IPAddress objects from the db
    query = context.session.query(models.IPAddress)

    (period_start, period_end) = billing.calc_periods(hour, minute)

    full_day_ips = billing.build_full_day_ips(query,
                                              period_start,
                                              period_end)
    partial_day_ips = billing.build_partial_day_ips(query,
                                                    period_start,
                                                    period_end)

    if notify:
        # '==================== Full Day ============================='
        for ipaddress in full_day_ips:
            click.echo('start: {}, end: {}'.format(period_start, period_end))
            payload = billing.build_payload(ipaddress,
                                            'ip.exists',
                                            start_time=period_start,
                                            end_time=period_end)
            billing.do_notify(context,
                              'ip.exists',
                              payload)
        # '==================== Part Day ============================='
        for ipaddress in partial_day_ips:
            click.echo('start: {}, end: {}'.format(period_start, period_end))
            payload = billing.build_payload(ipaddress,
                                            'ip.exists',
                                            start_time=ipaddress.allocated_at,
                                            end_time=period_end)
            billing.do_notify(context,
                              'ip.exists',
                              payload)
    else:
        click.echo('Case 1 ({}):\n'.format(len(full_day_ips)))
        for ipaddress in full_day_ips:
            pp(billing.build_payload(ipaddress,
                                     'ip.exists',
                                     start_time=period_start,
                                     end_time=period_end))

        click.echo('\n===============================================\n')

        click.echo('Case 2 ({}):\n'.format(len(partial_day_ips)))
        for ipaddress in partial_day_ips:
            pp(billing.build_payload(ipaddress,
                                     'ip.exists',
                                     start_time=ipaddress.allocated_at,
                                     end_time=period_end))


if __name__ == '__main__':
    main()
