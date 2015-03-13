import XenAPI

from quark.agent import xapi
from quark.tests import test_base

import mock


class TestVIF(test_base.TestBase):
    def test_str(self):
        rec = {"MAC": 2}
        self.assertEqual(str(xapi.VIF("1", rec, "3")), "1.2.3")

    def test_repr(self):
        rec = {"MAC": '2'}
        self.assertEqual(repr(xapi.VIF("1", rec, "3")), "VIF('1', '2', '3')")

    def test_eq(self):
        rec = {"MAC": '2'}
        self.assertEqual(xapi.VIF("1", rec, "3"), xapi.VIF("1", rec, "3"))

    def test_ne(self):
        rec1 = {"MAC": '2'}
        rec2 = {"MAC": '3'}
        vif1 = xapi.VIF("1", rec1, "4")
        vif2 = xapi.VIF("1", rec2, "4")
        vif3 = xapi.VIF("3", rec1, "4")
        vif4 = xapi.VIF("3", rec2, "4")

        self.assertNotEqual(vif1, vif2)
        self.assertNotEqual(vif1, vif3)
        self.assertNotEqual(vif1, vif4)


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
        instances = self.xclient.get_instances(self.session)
        vm = xapi.VM(ref="opaque1", uuid="uuid1",
                     dom_id="1", vifs=["opaque_vif1", "opaque_vif2"])
        self.assertEqual(instances, {"opaque1": vm})

    @mock.patch("quark.agent.xapi.XapiClient.get_instances")
    def test_get_interfaces(self, get_instances):
        instances = {"opaque1": xapi.VM(uuid="device_id1",
                                        ref="opaque1",
                                        vifs=["opaque_vif1"],
                                        dom_id="1")}
        get_instances.return_value = instances
        self.session.xenapi.VIF.get_all_records.return_value = {
            "opaque_vif1": {"VM": "opaque1", "MAC": "00:11:22:33:44:55"},
            "opaque_vif2": {"VM": "opaque2", "MAC": "55:44:33:22:11:00"},
        }
        interfaces = self.xclient.get_interfaces()
        rec = {"MAC": "00:11:22:33:44:55", "VM": "opaque1"}
        expected = set([xapi.VIF("device_id1", rec, "opaque_vif1")])
        self.assertEqual(interfaces, expected)

    @mock.patch("quark.agent.xapi.XapiClient.get_instances")
    def test_update_interfaces_added(self, get_instances):
        instances = {"opaque1": xapi.VM(uuid="device_id1",
                                        ref="opaque1",
                                        vifs=["opaque_vif1"],
                                        dom_id="1")}
        get_instances.return_value = instances
        rec = {"MAC": "00:11:22:33:44:55"}
        interfaces = [xapi.VIF("device_id1", rec,
                               "opaque_vif1")]

        dom_id = "1"
        vif_index = "0"

        vif_rec = {"device": vif_index, "VM": "opaqueref"}
        vm_rec = {"domid": dom_id}

        expected_args = dict(dom_id=dom_id, vif_index=vif_index)
        self.session.xenapi.VIF.get_record.return_value = vif_rec
        self.session.xenapi.VM.get_record.return_value = vm_rec
        self.xclient.update_interfaces(interfaces, [], [])

        xenapi_VIF = self.session.xenapi.VIF
        xenapi_VIF.add_to_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups", "enabled")
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)

        self.session.xenapi.host.call_plugin.assert_called_once_with(
            self.session.xenapi.session.get_this_host.return_value,
            "neutron_vif_flow", "online_instance_flows",
            expected_args)

    def test_update_interfaces_added_vm_removed(self):
        rec = {"MAC": "00:11:22:33:44:55"}
        interfaces = [xapi.VIF("device_id1", rec,
                               "opaque_vif1")]
        vif_index = "0"

        vif_rec = {"device": vif_index, "VM": "opaqueref"}

        self.session.xenapi.VIF.get_record.return_value = vif_rec
        self.session.xenapi.VM.get_record.side_effect = XenAPI.Failure(
            "HANDLE_INVALID")

        self.xclient.update_interfaces(interfaces, [], [])

        xenapi_VIF = self.session.xenapi.VIF
        xenapi_VIF.add_to_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups", "enabled")
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)

        self.assertEqual(self.session.xenapi.host.call_plugin.call_count, 0)

    def test_update_interfaces_updated(self):
        rec = {"MAC": "00:11:22:33:44:55"}
        interfaces = [xapi.VIF("device_id1", rec,
                               "opaque_vif1")]

        dom_id = "1"
        vif_index = "0"

        vif_rec = {"device": vif_index, "VM": "opaqueref"}
        vm_rec = {"domid": dom_id}

        expected_args = dict(dom_id=dom_id, vif_index=vif_index)
        self.session.xenapi.VIF.get_record.return_value = vif_rec
        self.session.xenapi.VM.get_record.return_value = vm_rec

        self.xclient.update_interfaces([], interfaces, [])

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)

        expected_args = dict(dom_id="1", vif_index="0")
        self.session.xenapi.host.call_plugin.assert_called_once_with(
            self.session.xenapi.session.get_this_host.return_value,
            "neutron_vif_flow", "online_instance_flows",
            expected_args)

    def test_update_interfaces_removed(self):
        rec = {"MAC": "00:11:22:33:44:55"}
        interfaces = [xapi.VIF("device_id1", rec,
                               "opaque_vif1")]

        dom_id = "1"
        vif_index = "0"

        vif_rec = {"device": vif_index, "VM": "opaqueref"}
        vm_rec = {"domid": dom_id}

        expected_args = dict(dom_id=dom_id, vif_index=vif_index)
        self.session.xenapi.VIF.get_record.return_value = vif_rec
        self.session.xenapi.VM.get_record.return_value = vm_rec
        self.xclient.update_interfaces([], [], interfaces)

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)
        xenapi_VIF.remove_from_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups")

        self.session.xenapi.host.call_plugin.assert_called_once_with(
            self.session.xenapi.session.get_this_host.return_value,
            "neutron_vif_flow", "online_instance_flows",
            expected_args)

    def test_update_interfaces_removed_vm_removed(self):
        rec = {"MAC": "00:11:22:33:44:55"}
        interfaces = [xapi.VIF("device_id1", rec,
                               "opaque_vif1")]

        self.session.xenapi.VIF.get_record.side_effect = XenAPI.Failure(
            "HANDLE_INVALID")
        self.session.xenapi.VM.get_record.return_value = XenAPI.Failure(
            "HANDLE_INVALID")
        self.xclient.update_interfaces([], [], interfaces)

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)
        xenapi_VIF.remove_from_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups")

        self.assertEqual(self.session.xenapi.host.call_plugin.call_count, 0)

    def test_update_interfaces_none(self):
        self.xclient.update_interfaces([], [], [])

        xenapi_VIF = self.session.xenapi.VIF
        self.assertEqual(xenapi_VIF.remove_from_other_config.call_count, 0)
        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)

        self.assertEqual(self.session.xenapi.host.call_plugin.call_count, 0)

    def test_update_interfaces_removed_raises(self):
        rec = {"MAC": "00:11:22:33:44:55"}
        interfaces = [xapi.VIF("device_id1", rec,
                               "opaque_vif1")]

        dom_id = "1"
        vif_index = "0"

        vif_rec = {"device": vif_index, "VM": "opaqueref"}
        vm_rec = {"domid": dom_id}

        expected_args = dict(dom_id=dom_id, vif_index=vif_index)
        self.session.xenapi.VIF.get_record.return_value = vif_rec
        self.session.xenapi.VM.get_record.return_value = vm_rec
        xenapi_VIF = self.session.xenapi.VIF

        # Without the try/except in _unset, this raises and the test fails
        xenapi_VIF.remove_from_other_config.side_effect = XenAPI.Failure(
            "HANDLE_INVALID")

        self.xclient.update_interfaces([], [], interfaces)

        self.assertEqual(xenapi_VIF.add_to_other_config.call_count, 0)
        xenapi_VIF.remove_from_other_config.assert_called_once_with(
            "opaque_vif1", "security_groups")

        self.session.xenapi.host.call_plugin.assert_called_once_with(
            self.session.xenapi.session.get_this_host.return_value,
            "neutron_vif_flow", "online_instance_flows",
            expected_args)


class TestXapiSession(test_base.TestBase):
    def setUp(self):
        patcher = mock.patch("quark.agent.xapi.XenAPI.Session")
        self.addCleanup(patcher.stop)
        self.session = patcher.start().return_value

    @mock.patch("quark.agent.xapi.XapiClient._session")
    def test_sessioned_exception_handling(self, xapi_session):
        xapi_session.side_effect = XenAPI.Failure("HANDLE_INVALID")
        with self.assertRaises(XenAPI.Failure):
            xapi.XapiClient()
            self.session.logout.assert_called_once()
