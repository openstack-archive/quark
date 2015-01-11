from quark.agent import xapi
from quark.tests import test_base

import mock


class TestVIF(test_base.TestBase):
    def test_str(self):
        self.assertEqual(str(xapi.VIF("1", "2", "3")), "1.2.3")

    def test_repr(self):
        self.assertEqual(repr(xapi.VIF("1", "2", "3")), "VIF('1', '2', '3')")

    def test_eq(self):
        self.assertEqual(xapi.VIF("1", "2", "3"), xapi.VIF("1", "2", "3"))

    def test_ne(self):
        self.assertNotEqual(xapi.VIF("1", "2", "4"), xapi.VIF("1", "3", "4"))
        self.assertNotEqual(xapi.VIF("1", "2", "4"), xapi.VIF("3", "2", "4"))
        self.assertNotEqual(xapi.VIF("1", "2", "4"), xapi.VIF("3", "4", "4"))

    def test_hashable(self):
        self.assertEqual(
            tuple(set([xapi.VIF("1", "2", "3"), xapi.VIF("1", "2", "3")])),
            (xapi.VIF("1", "2", "3"),))

    def test_from_string(self):
        self.assertEqual(xapi.VIF.from_string("1.2.3"),
                         xapi.VIF("1", "2", "3"))


class TestXapiClient(test_base.TestBase):
    def setUp(self):
        patcher = mock.patch("quark.agent.xapi.XenAPI.Session")
        self.addCleanup(patcher.stop)
        self.session = patcher.start().return_value
        self.xclient = xapi.XapiClient()

    def test_get_instances(self):
        self.session.xenapi.VM.get_all_records.return_value = {
            "opaque1": {"other_config": {"nova_uuid": "uuid1"},
                        "power_state": "running", "is_a_template": False,
                        "is_control_domain": False,
                        "name_label": "instance-1",
                        "VIFs": ["opaque_vif1", "opaque_vif2"],
                        "domid": "1"},
            "opaque2": {"other_config": {},
                        "power_state": "", "is_a_template": True,
                        "is_control_domain": True,
                        "name_label": "",
                        "VIFs": [],
                        "domid": "2"},
        }
        instances = self.xclient.get_instances()
        vm = xapi.VM(ref="opaque1", uuid="uuid1",
                     dom_id="1", vifs=["opaque_vif1", "opaque_vif2"])
        self.assertEqual(instances, {"opaque1": vm})

    def test_get_interfaces(self):
        instances = {"opaque1": xapi.VM(uuid="device_id1",
                                        ref="opaque1",
                                        vifs=["opaque_vif1"],
                                        dom_id="1")}
        self.session.xenapi.VIF.get_all_records.return_value = {
            "opaque_vif1": {"VM": "opaque1", "MAC": "00:11:22:33:44:55"},
            "opaque_vif2": {"VM": "opaque2", "MAC": "55:44:33:22:11:00"},
        }
        interfaces = self.xclient.get_interfaces(instances)
        self.assertEqual(interfaces,
                         set([xapi.VIF("device_id1", "00:11:22:33:44:55",
                                       "opaque_vif1")]))

    def test_update_interfaces_added(self):
        instances = {"opaque1": xapi.VM(uuid="device_id1",
                                        ref="opaque1",
                                        vifs=["opaque_vif1"],
                                        dom_id="1")}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55",
                               "opaque_vif1")]

        self.xclient.update_interfaces(instances, interfaces, [], [])

        xenapi_VIF = self.session.xenapi.VIF
        xenapi_VIF.add_to_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups", "enabled")
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)

        expected_args = dict(dom_id="1", vif_index="0")
        self.session.xenapi.host.call_plugin.assert_called_once_with(
            self.session.xenapi.session.get_this_host.return_value,
            "neutron_vif_flow", "online_instance_flows",
            expected_args)

    def test_update_interfaces_added_vm_removed(self):
        instances = {}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55",
                               "opaque_vif1")]

        self.xclient.update_interfaces(instances, interfaces, [], [])

        xenapi_VIF = self.session.xenapi.VIF
        xenapi_VIF.add_to_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups", "enabled")
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)

        self.assertEqual(self.session.xenapi.host.call_plugin.call_count, 0)

    def test_update_interfaces_updated(self):
        instances = {"opaque1": xapi.VM(uuid="device_id1",
                                        ref="opaque1",
                                        vifs=["opaque_vif1"],
                                        dom_id="1")}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55",
                               "opaque_vif1")]

        self.xclient.update_interfaces(instances, [], interfaces, [])

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)

        expected_args = dict(dom_id="1", vif_index="0")
        self.session.xenapi.host.call_plugin.assert_called_once_with(
            self.session.xenapi.session.get_this_host.return_value,
            "neutron_vif_flow", "online_instance_flows",
            expected_args)

    def test_update_interfaces_removed(self):
        instances = {"opaque1": xapi.VM(uuid="device_id1",
                                        ref="opaque1",
                                        vifs=["opaque_vif1"],
                                        dom_id="1")}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55",
                               "opaque_vif1")]

        self.xclient.update_interfaces(instances, [], [], interfaces)

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)
        xenapi_VIF.remove_from_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups")

        expected_args = dict(dom_id="1", vif_index="0")
        self.session.xenapi.host.call_plugin.assert_called_once_with(
            self.session.xenapi.session.get_this_host.return_value,
            "neutron_vif_flow", "online_instance_flows",
            expected_args)

    def test_update_interfaces_removed_vm_removed(self):
        instances = {}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55",
                               "opaque_vif1")]

        self.xclient.update_interfaces(instances, [], [], interfaces)

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)
        xenapi_VIF.remove_from_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups")

        self.assertEqual(self.session.xenapi.host.call_plugin.call_count, 0)

    def test_update_interfaces_none(self):
        instances = {"opaque1": "device_id1"}

        self.xclient.update_interfaces(instances, [], [], [])

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)

        self.assertEqual(self.session.xenapi.host.call_plugin.call_count, 0)
