import json

from quark.agent import xapi
from quark.tests import test_base

import mock


class TestVIF(test_base.TestBase):
    def test_str(self):
        self.assertEqual(str(xapi.VIF("1", "2")), "1.2")

    def test_repr(self):
        self.assertEqual(repr(xapi.VIF("1", "2")), "VIF('1', '2')")

    def test_eq(self):
        self.assertEqual(xapi.VIF("1", "2"), xapi.VIF("1", "2"))

    def test_ne(self):
        self.assertNotEqual(xapi.VIF("1", "2"), xapi.VIF("1", "3"))
        self.assertNotEqual(xapi.VIF("1", "2"), xapi.VIF("3", "2"))
        self.assertNotEqual(xapi.VIF("1", "2"), xapi.VIF("3", "4"))

    def test_hashable(self):
        self.assertEqual(tuple(set([xapi.VIF("1", "2"), xapi.VIF("1", "2")])),
                         (xapi.VIF("1", "2"),))

    def test_from_string(self):
        self.assertEqual(xapi.VIF.from_string("1.2"), xapi.VIF("1", "2"))


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
                        "name_label": "instance-1"},
            "opaque2": {"other_config": {},
                        "power_state": "", "is_a_template": True,
                        "is_control_domain": True,
                        "name_label": ""},
        }
        instances = self.xclient.get_instances()
        self.assertEqual(instances, {"opaque1": "uuid1"})

    def test_get_interfaces(self):
        instances = {"opaque1": "device_id1"}
        self.session.xenapi.VIF.get_all_records.return_value = {
            "opaque_vif1": {"VM": "opaque1", "MAC": "00:11:22:33:44:55"},
            "opaque_vif2": {"VM": "opaque2", "MAC": "55:44:33:22:11:00"},
        }
        interfaces = self.xclient.get_interfaces(instances)
        self.assertEqual(interfaces,
                         set([xapi.VIF("device_id1", "00:11:22:33:44:55")]))

    def test_update_interfaces_added(self):
        instances = {"opaque1": "device_id1"}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55")]
        location = "vm-data/networking/001122334455"
        vm = {"xenstore_data": {location: json.dumps({"key": "value"})}}
        self.session.xenapi.VM.get_record.return_value = vm

        self.xclient.update_interfaces(instances, interfaces, [], [])

        xenapi_VM = self.session.xenapi.VM
        xenapi_VM.get_record.assert_called_once_with("opaque1")
        xenapi_VM.remove_from_xenstore_data.assert_called_once_with(
            "opaque1", location)
        new_data = json.dumps({"failmode": "secure", "key": "value"})
        xenapi_VM.add_to_xenstore_data.assert_called_once_with(
            "opaque1", location, new_data)

        expected_args_1 = dict(
            host_uuid=self.session.xenapi.host.get_uuid.return_value,
            path=location,
            value=new_data,
            dom_id=self.session.xenapi.VM.get_domid.return_value)
        expected_args_2 = dict(
            host_uuid=self.session.xenapi.host.get_uuid.return_value,
            uuid="device_id1")
        self.session.xenapi.host.call_plugin.assert_has_calls([
            mock.call(self.session.xenapi.session.get_this_host.return_value,
                      "xenstore.py", "write_record", expected_args_1),
            mock.call(self.session.xenapi.session.get_this_host.return_value,
                      "post_live_migrate", "instance_post_live_migration",
                      expected_args_2)])

    def test_update_interfaces_updated(self):
        instances = {"opaque1": "device_id1"}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55")]
        location = "vm-data/networking/001122334455"
        vm = {"xenstore_data": {location: json.dumps({"key": "value"})}}
        self.session.xenapi.VM.get_record.return_value = vm

        self.xclient.update_interfaces(instances, [], interfaces, [])

        xenapi_VM = self.session.xenapi.VM
        self.assertEqual(xenapi_VM.get_record.call_count, 0)
        self.assertEqual(xenapi_VM.remove_from_xenstore_data.call_count, 0)
        self.assertEqual(xenapi_VM.add_to_xenstore_data.call_count, 0)

        expected_args_2 = dict(
            host_uuid=self.session.xenapi.host.get_uuid.return_value,
            uuid="device_id1")
        self.session.xenapi.host.call_plugin.assert_has_calls([
            mock.call(self.session.xenapi.session.get_this_host.return_value,
                      "post_live_migrate", "instance_post_live_migration",
                      expected_args_2)])

    def test_update_interfaces_removed(self):
        instances = {"opaque1": "device_id1"}
        interfaces = [xapi.VIF("device_id1", "00:11:22:33:44:55")]
        location = "vm-data/networking/001122334455"
        vm = {"xenstore_data": {location: json.dumps({
            "failmode": "secure", "key": "value"})}}
        self.session.xenapi.VM.get_record.return_value = vm

        self.xclient.update_interfaces(instances, [], [], interfaces)

        xenapi_VM = self.session.xenapi.VM
        xenapi_VM.get_record.assert_called_once_with("opaque1")
        xenapi_VM.remove_from_xenstore_data.assert_called_once_with(
            "opaque1", location)
        new_data = json.dumps({"key": "value"})
        xenapi_VM.add_to_xenstore_data.assert_called_once_with(
            "opaque1", location, new_data)

        expected_args_1 = dict(
            host_uuid=self.session.xenapi.host.get_uuid.return_value,
            path=location,
            value=new_data,
            dom_id=self.session.xenapi.VM.get_domid.return_value)
        expected_args_2 = dict(
            host_uuid=self.session.xenapi.host.get_uuid.return_value,
            uuid="device_id1")
        self.session.xenapi.host.call_plugin.assert_has_calls([
            mock.call(self.session.xenapi.session.get_this_host.return_value,
                      "xenstore.py", "write_record", expected_args_1),
            mock.call(self.session.xenapi.session.get_this_host.return_value,
                      "post_live_migrate", "instance_post_live_migration",
                      expected_args_2)])

    def test_update_interfaces_none(self):
        instances = {"opaque1": "device_id1"}
        location = "vm-data/networking/001122334455"
        vm = {"xenstore_data": {location: json.dumps({"key": "value"})}}
        self.session.xenapi.VM.get_record.return_value = vm

        self.xclient.update_interfaces(instances, [], [], [])

        xenapi_VM = self.session.xenapi.VM
        self.assertEqual(xenapi_VM.get_record.call_count, 0)
        self.assertEqual(xenapi_VM.remove_from_xenstore_data.call_count, 0)
        self.assertEqual(xenapi_VM.add_to_xenstore_data.call_count, 0)

        self.assertEqual(self.session.xenapi.host.call_plugin.call_count, 0)
