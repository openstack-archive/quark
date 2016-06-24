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
import time

from neutron.common import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging as messaging
from oslo_messaging import exceptions as om_exc

from quark.db import api as db_api
from quark.plugin_modules import jobs as job_api
from quark.plugin_modules import ports as port_api
from quark.worker_plugins import base_worker


CONF = cfg.CONF
LOG = logging.getLogger(__name__)
CONSUMER_TOPIC = 'quark_sg_update_consumer'
PRODUCER_TOPIC = 'quark_sg_update_producer'
SG_UPDATE_TOPIC = 'quark_sg_update'
VERSION = "1.0"


"""
============================================================
QuarkSGAsyncProcess
============================================================
"""


class QuarkSGAsyncProcessCallback(object):
    target = messaging.Target(version='1.0', namespace=None)

    def update_sg(self, context, sg, rule_id, action):
        db_sg = db_api.security_group_find(context, id=sg, scope=db_api.ONE)
        if not db_sg:
            return None
        with context.session.begin():
            job_body = dict(action="%s sg rule %s" % (action, rule_id),
                            resource_id=rule_id,
                            tenant_id=db_sg['tenant_id'])
            job_body = dict(job=job_body)
            job = job_api.create_job(context, job_body)
            rpc_client = QuarkSGAsyncProducerClient()
            try:
                rpc_client.populate_subtasks(context, sg, job['id'])
            except om_exc.MessagingTimeout:
                LOG.error("Failed to create subtasks. Rabbit running?")
                return None
        return {"job_id": job['id']}


class QuarkSGAsyncProcess(base_worker.QuarkAsyncPluginBase):
    versions = [VERSION]

    def __init__(self, topic=SG_UPDATE_TOPIC):
        super(QuarkSGAsyncProcess, self).__init__(topic)
        self.callbacks = [QuarkSGAsyncProcessCallback()]


class QuarkSGAsyncProcessClient(object):
    """This class is used for testing QuarkRpcTestCallback."""
    def __init__(self):
        topic = SG_UPDATE_TOPIC
        target = messaging.Target(topic=topic)
        self.client = n_rpc.get_client(target)

    def start_update(self, context, sg, rule_id, action):
        cctxt = self.client.prepare(version='1.0')
        try:
            return cctxt.call(context, 'update_sg', sg=sg, rule_id=rule_id,
                              action=action)
        except om_exc.MessagingTimeout:
            return None


"""
============================================================
QuarkSGAsyncProducer
============================================================
"""


class QuarkSGProducerCallback(object):
    target = messaging.Target(version='1.0', namespace=None)

    def populate_subtasks(self, context, sg, parent_job_id):
        db_sg = db_api.security_group_find(context, id=sg, scope=db_api.ONE)
        if not db_sg:
            return None
        ports = db_api.sg_gather_associated_ports(context, db_sg)
        if len(ports) == 0:
            return {"ports": 0}
        for port in ports:
            job_body = dict(action="update port %s" % port['id'],
                            tenant_id=db_sg['tenant_id'],
                            resource_id=port['id'],
                            parent_id=parent_job_id)
            job_body = dict(job=job_body)
            job = job_api.create_job(context, job_body)
            rpc_consumer = QuarkSGAsyncConsumerClient()
            try:
                rpc_consumer.update_port(context, port['id'], job['id'])
            except om_exc.MessagingTimeout:
                # TODO(roaet): Not too sure what can be done here other than
                # updating the job as a failure?
                LOG.error("Failed to update port. Rabbit running?")
        return None


class QuarkSGAsyncProducer(base_worker.QuarkAsyncPluginBase):
    versions = [VERSION]

    def __init__(self, topic=PRODUCER_TOPIC):
        super(QuarkSGAsyncProducer, self).__init__(topic)
        self.callbacks = [QuarkSGProducerCallback()]


class QuarkSGAsyncProducerClient(object):
    """This class is used for testing QuarkRpcTestCallback."""
    def __init__(self):
        topic = PRODUCER_TOPIC
        target = messaging.Target(topic=topic)
        self.client = n_rpc.get_client(target)

    def populate_subtasks(self, context, sg, parent_job_id):
        cctxt = self.client.prepare(version='1.0')
        return cctxt.cast(context, 'populate_subtasks', sg=sg,
                          parent_job_id=parent_job_id)


"""
============================================================
QuarkSGAsyncConsumer
============================================================
"""


class QuarkSGConsumerCallback(object):
    target = messaging.Target(version='1.0', namespace=None)

    def update_ports_for_sg(self, context, portid, jobid):
        port = db_api.port_find(context, id=portid, scope=db_api.ONE)
        if not port:
            LOG.warning("Port not found")
            return
        net_driver = port_api._get_net_driver(port.network, port=port)
        base_net_driver = port_api._get_net_driver(port.network)
        sg_list = [sg for sg in port.security_groups]

        success = False
        error = None
        retries = 3
        retry_delay = 2
        for retry in xrange(retries):
            try:
                net_driver.update_port(context, port_id=port["backend_key"],
                                       mac_address=port["mac_address"],
                                       device_id=port["device_id"],
                                       base_net_driver=base_net_driver,
                                       security_groups=sg_list)
                success = True
                error = None
                break
            except Exception as error:
                LOG.warning("Could not connect to redis, but retrying soon")
                time.sleep(retry_delay)
        status_str = ""
        if not success:
            status_str = "Port %s update failed after %d tries. Error: %s" % (
                portid, retries, error)
        update_body = dict(completed=True, status=status_str)
        update_body = dict(job=update_body)
        job_api.update_job(context, jobid, update_body)


class QuarkSGAsyncConsumer(base_worker.QuarkAsyncPluginBase):
    versions = [VERSION]

    def __init__(self, topic=CONSUMER_TOPIC):
        super(QuarkSGAsyncConsumer, self).__init__(topic)
        self.callbacks = [QuarkSGConsumerCallback()]


class QuarkSGAsyncConsumerClient(object):
    """This class is used for testing QuarkRpcTestCallback."""
    def __init__(self):
        topic = CONSUMER_TOPIC
        target = messaging.Target(topic=topic)
        self.client = n_rpc.get_client(target)

    def update_port(self, context, portid, jobid):
        cctxt = self.client.prepare(version='1.0')
        return cctxt.cast(context, 'update_ports_for_sg', portid=portid,
                          jobid=jobid)
