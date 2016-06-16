#!/usr/bin/python
# Copyright 2014 Rackspace Hosting Inc.
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

"""Quark Redis Security Groups CLI tool.

Usage: redis_sg_tool [-h] [--config-file=PATH] [--retries=<retries>]
                     [--retry-delay=<delay>] <command> [--yarly]

Options:
    -h --help  Show this screen.
    --version  Show version.
    --config-file=PATH  Use a different config file path
    --retries=<retries>  Number of times to re-attempt some operations
    --retry-delay=<delay>  Amount of time to wait between retries

Available commands are:
    redis_sg_tool test-connection
    redis_sg_tool vifs-in-redis
    redis_sg_tool num-groups
    redis_sg_tool ports-with-groups
    redis_sg_tool purge-orphans [--yarly]
    redis_sg_tool write-groups [--yarly]
    redis_sg_tool -h | --help
    redis_sg_tool --version

"""
import sys
import time

import docopt
import netaddr
from neutron.common import config
import neutron.context
from oslo_config import cfg

from quark.cache import security_groups_client as sg_client
from quark.db import api as db_api
from quark import exceptions as q_exc

VERSION = 0.1
RETRIES = 5
RETRY_DELAY = 1


class QuarkRedisTool(object):
    def __init__(self, arguments):
        self._args = arguments

        self._retries = RETRIES
        self._retry_delay = RETRY_DELAY

        if self._args.get("--retries"):
            self._retries = int(self._args["--retries"])

        if self._args.get("--retry-delay"):
            self._retry_delay = int(self._args["--retry-delay"])

        config_args = []
        if self._args.get("--config-file"):
            config_args.append("--config-file=%s" %
                               self._args.pop("--config-file"))

        self._dryrun = not self._args.get("--yarly")

        config.init(config_args)
        if not cfg.CONF.config_file:
            sys.exit(_("ERROR: Unable to find configuration file via the "
                       "default search paths (~/.neutron/, ~/, /etc/neutron/, "
                       "/etc/) and the '--config-file' option!"))

    def dispatch(self):
        command = self._args.get("<command>")
        if command == "test-connection":
            self.test_connection()
        elif command == "vifs-in-redis":
            self.vif_count()
        elif command == "num-groups":
            self.num_groups()
        elif command == "ports-with-groups":
            self.ports_with_groups()
        elif command == "purge-orphans":
            self.purge_orphans(self._dryrun)
        elif command == "write-groups":
            self.write_groups(self._dryrun)
        else:
            print("Redis security groups tool. Re-run with -h/--help for "
                  "options")

    def _get_connection(self, giveup=True):
        client = sg_client.SecurityGroupsClient()
        try:
            if client.ping():
                return client
        except Exception as e:
            print(e)
            if giveup:
                print("Giving up...")
                sys.exit(1)

    def test_connection(self):
        client = self._get_connection()
        if client:
            print("Connected Successfully")
            return True
        else:
            print("Could not connect to Redis")
            return False

    def vif_count(self):
        client = self._get_connection()
        print(len(client.vif_keys(field=sg_client.SECURITY_GROUP_HASH_ATTR)))

    def num_groups(self):
        ctx = neutron.context.get_admin_context()
        print(db_api.security_group_count(ctx))

    def ports_with_groups(self):
        ctx = neutron.context.get_admin_context()
        print(db_api.ports_with_security_groups_count(ctx))

    def purge_orphans(self, dryrun=False):
        client = self._get_connection()
        ctx = neutron.context.get_admin_context()
        ports_with_groups = db_api.ports_with_security_groups_find(ctx).all()
        if dryrun:
            print()
            print("Purging orphans in dry run mode. Existing rules in Redis "
                  "will be checked against those in the database. If any "
                  "are found in Redis but lack matching database rules, "
                  "they'll be deleted from the database.\n\nTo actually "
                  "apply the groups, re-run with the --yarly flag.")
            print()
            print("Found %s ports with security groups" %
                  len(ports_with_groups))

        # Pre-spin the list of orphans
        vifs = {}
        for vif in client.vif_keys():
            vifs[vif] = False

        if dryrun:
            print("Found %d VIFs in Redis" % len(vifs))

        # Pop off the ones we find in the database
        for port in ports_with_groups:
            vif_key = client.vif_key(port["device_id"], port["mac_address"])
            vifs.pop(vif_key, None)

        if dryrun:
            print("Found %d orphaned VIF rule sets" % len(vifs))
            print('=' * 80)

        for orphan in vifs.keys():
            if dryrun:
                print("VIF %s is orphaned" % orphan)
            else:
                for retry in xrange(self._retries):
                    try:
                        client.delete_key(orphan)
                        break
                    except q_exc.RedisConnectionFailure:
                        time.sleep(self._retry_delay)
                        client = self._get_connection(giveup=False)
        if dryrun:
            print('=' * 80)
            print()
            print("Re-run with --yarly to apply changes")

        print("Done!")

    def write_groups(self, dryrun=False):
        client = self._get_connection()
        ctx = neutron.context.get_admin_context()
        ports_with_groups = db_api.ports_with_security_groups_find(ctx).all()
        if dryrun:
            print()
            print("Writing groups in dry run mode. Existing rules in Redis "
                  "will be checked against those in the database, with a "
                  "running report generated of all those that will be "
                  "overwritten.\n\nTo actually apply the groups, re-run "
                  "with the --yarly flag.")
            print()
            print("Found %s ports with security groups" %
                  len(ports_with_groups))

        if dryrun:
            vifs = len(client.vif_keys())
            if vifs > 0:
                print("There are %d VIFs with rules in Redis, some of which "
                      "may be overwritten!" % vifs)
                print()

        overwrite_count = 0
        for port in ports_with_groups:
            mac = netaddr.EUI(port["mac_address"])

            # Rather than loading everything in one giant chunk, we'll make
            # trips per port.
            group_ids = [g["id"] for g in port.security_groups]
            rules = db_api.security_group_rule_find(ctx, group_id=group_ids,
                                                    scope=db_api.ALL)

            if dryrun:
                existing_rules = client.get_rules_for_port(port["device_id"],
                                                           port["mac_address"])
                if existing_rules:
                    overwrite_count += 1
                    db_len = len(rules)
                    existing_len = len(existing_rules["rules"])
                    print("== Port ID:%s - MAC:%s - Device ID:%s - "
                          "Redis Rules:%d - DB Rules:%d" %
                          (port["id"], mac, port["device_id"], existing_len,
                           db_len))

            if not dryrun:
                for retry in xrange(self._retries):
                    try:
                        payload = client.serialize_rules(rules)
                        client.apply_rules(
                            port["device_id"], port["mac_address"], payload)
                        break
                    except q_exc.RedisConnectionFailure:
                        time.sleep(self._retry_delay)
                        client = self._get_connection(giveup=False)

        if dryrun:
            print()
            print("Total number of VIFs to overwrite/were overwritten: %s" %
                  overwrite_count)
            diff = vifs - overwrite_count
            if diff > 0:
                print("Orphaned VIFs in Redis:", diff)
                print("Run purge-orphans to clean then up")

        if dryrun:
            print("Total number of VIFs to write: %d" %
                  len(ports_with_groups))

        if dryrun:
            print('=' * 80)
            print("Re-run with --yarly to apply changes")
        print("Done!")


def main():
    arguments = docopt.docopt(__doc__,
                              version="Quark Redis CLI %.2f" % VERSION)
    redis_tool = QuarkRedisTool(arguments)
    redis_tool.dispatch()


if __name__ == "__main__":
    main()
