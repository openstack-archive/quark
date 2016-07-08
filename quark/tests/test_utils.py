import mock

from neutron_lib import exceptions as n_exc
from quark.tests import test_base
from quark import utils
import webob


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


class TestExcWrapper(test_base.TestBase):

    @utils.exc_wrapper
    def raise_not_found(self):
        raise n_exc.NotFound()

    @utils.exc_wrapper
    def raise_conflict(self):
        raise n_exc.Conflict()

    @utils.exc_wrapper
    def raise_bad_request(self):
        raise n_exc.BadRequest(resource="test_bad_request", msg="testing")

    @utils.exc_wrapper
    def raise_generic_exception(self):
        raise Exception()

    @utils.exc_wrapper
    def no_raise(self):
        return ""

    def test_http_not_found(self):
        with self.assertRaises(webob.exc.HTTPNotFound):
            self.raise_not_found()

    def test_http_conflict(self):
        with self.assertRaises(webob.exc.HTTPConflict):
            self.raise_conflict()

    def test_http_bad_request(self):
        with self.assertRaises(webob.exc.HTTPBadRequest):
            self.raise_bad_request()

    def test_http_server_error(self):
        with self.assertRaises(webob.exc.HTTPInternalServerError):
            self.raise_generic_exception()

    def test_no_raise(self):
        self.assertEqual("", self.no_raise())
