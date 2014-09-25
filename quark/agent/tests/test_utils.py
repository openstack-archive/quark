import mock

from quark.agent import utils
from quark.tests import test_base


class TestRetryLoop(test_base.TestBase):
    def test_retry_3_times_pass(self):
        r = utils.retry_loop(3)
        c = mock.MagicMock()
        g = r(c)
        ret = g()
        c.assert_called_once_with()
        self.assertEqual(ret, c.return_value)

    def test_retry_3_times_exception(self):
        r = utils.retry_loop(3)
        c = mock.MagicMock()
        g = r(c)
        c.side_effect = ValueError()
        with self.assertRaises(ValueError):
            g()
        self.assertEqual(c.call_count, 3)

    def test_retry_3_times_exception_pass(self):
        r = utils.retry_loop(3)
        c = mock.MagicMock()
        g = r(c)
        expected_ret = mock.MagicMock()
        c.side_effect = (ValueError(), expected_ret)
        ret = g()
        self.assertEqual(c.call_count, 2)
        self.assertEqual(ret, expected_ret)
