# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid
# Copyright (c) 2018 Future Internet Consulting and Development Solutions S.L.

# This file is part of OAuth2 CKAN Extension.

# OAuth2 CKAN Extension is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# OAuth2 CKAN Extension is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with OAuth2 CKAN Extension.  If not, see <http://www.gnu.org/licenses/>.

from base64 import b64decode, b64encode
import threading
import unittest
import json

from mock import MagicMock
from parameterized import parameterized

from ckanext.oauth2 import controller, plugin


RETURNED_STATUS = 302
EXAMPLE_FLASH = 'This is a test'
EXCEPTION_MSG = 'Invalid'
CAME_FROM_FIELD = 'came_from'


class CompleteException(Exception):
    description = 'Exception description'
    error = 'Exception error'


class ErrorException(Exception):
    error = 'Exception error 2'


class VoidException(Exception):
    pass


class OAuth2PluginTest(unittest.TestCase):

    def setUp(self):
        # Save the response, the request and the helper functions and mock them
        self._helpers = controller.helpers
        controller.helpers = MagicMock()

        self._oauth2 = controller.oauth2
        controller.oauth2 = MagicMock()

        self._toolkit_controller = controller.toolkit
        self._toolkit_plugin = plugin.toolkit
        plugin.toolkit = controller.toolkit = MagicMock()

        self.__session = controller.session
        controller.session = MagicMock()

        self.controller = controller.OAuth2Controller()

    def tearDown(self):
        # Unmock the function
        controller.helpers = self._helpers
        controller.oauth2 = self._oauth2
        controller.toolkit = self._toolkit_controller
        controller.session = self.__session
        plugin.toolkit = self._toolkit_plugin

    def generate_state(self, url):
        return b64encode(bytes(json.dumps({CAME_FROM_FIELD: url})))

    def get_came_from(self, state):
        return json.loads(b64decode(state)).get(CAME_FROM_FIELD, '/')

    def test_callback_no_errors(self):
        oauth2Helper = controller.oauth2.OAuth2Helper.return_value

        token = 'TOKEN'
        user_id = 'user_id'
        oauth2Helper.get_token.return_value = token
        oauth2Helper.identify.return_value = user_id

        # Call the controller
        self.controller.callback()

        oauth2Helper.get_token.assert_called_once()
        oauth2Helper.identify.assert_called_once_with(token)
        oauth2Helper.remember.assert_called_once_with(user_id)
        oauth2Helper.update_token.assert_called_once_with(user_id, token)
        oauth2Helper.redirect_from_callback.assert_called_once_with()

    @parameterized.expand([
        (),
        ('/',),
        ('/', CompleteException(EXCEPTION_MSG), None, EXCEPTION_MSG),
        ('/', CompleteException(), None, CompleteException.description),
        ('/', ErrorException(EXCEPTION_MSG), None, EXCEPTION_MSG),
        ('/', ErrorException(), None, ErrorException.error),
        ('/', VoidException(EXCEPTION_MSG), None, EXCEPTION_MSG),
        ('/', VoidException(), None, type(VoidException()).__name__),
        ('/about', Exception(EXCEPTION_MSG), EXAMPLE_FLASH, EXAMPLE_FLASH)
    ])
    def test_callback_errors(self, came_from=None, exception=Exception(EXCEPTION_MSG),
                               error_description=None, expected_flash=EXCEPTION_MSG):

        # Recover function
        controller.oauth2.get_came_from = self.get_came_from

        oauth2Helper = controller.oauth2.OAuth2Helper.return_value
        oauth2Helper.get_token.side_effect = exception

        controller.toolkit.request.GET = {}
        controller.toolkit.request.GET['state'] = self.generate_state(came_from)
        if error_description is not None:
            controller.toolkit.request.GET['error_description'] = error_description
        controller.toolkit.request.params.get = controller.toolkit.request.GET.get

        # Call the controller
        self.controller.callback()

        # Check the state and the location
        self.assertEquals(RETURNED_STATUS, controller.toolkit.response.status_int)
        self.assertEquals(came_from, controller.toolkit.response.location)
        controller.helpers.flash_error.assert_called_once_with(expected_flash)

    @parameterized.expand([
        (),
        (None,                        None,               '/dashboard'),
        ('/about',                    None,               '/about'),
        ('/about',                    '/ckan-admin',      '/ckan-admin'),
        (None,                        '/ckan-admin',      '/ckan-admin'),
        ('/',                         None,               '/dashboard'),
        ('/user/logged_out_redirect', None,               '/dashboard'),
        ('/',                         '/ckan-admin',      '/ckan-admin'),
        ('/user/logged_out_redirect', '/ckan-admin',      '/ckan-admin'),
        ('http://google.es',          None,               '/dashboard'),
        ('http://google.es',          None,               '/dashboard')
    ])
    def test_login(self, referer=None, came_from=None, expected_referer='/dashboard'):

        # The login function will check these variables
        controller.toolkit.request.headers = {}
        controller.toolkit.request.params = {}

        if referer:
            controller.toolkit.request.headers['Referer'] = referer

        if came_from:
            controller.toolkit.request.params['came_from'] = came_from

        # Call the function
        self.controller.login()

        self.controller.oauth2helper.challenge.assert_called_once_with(expected_referer)


class MailAdminsTest(unittest.TestCase):
    """Regression tests for the sysadmin access-request notification.

    After the CKAN 2.11 upgrade this email stopped arriving in some
    environments while every other email still worked. The cause was not the
    send itself but recipient selection: when the query matched no usable
    sysadmin the loop body simply never ran, so nothing was sent and nothing
    was logged. These tests pin down that the no-recipient cases are now
    reported instead of passing silently.
    """

    def _admin(self, name, email, state='active', sysadmin=True):
        admin = MagicMock()
        admin.name = name
        admin.fullname = name
        admin.email = email
        admin.state = state
        admin.sysadmin = sysadmin
        return admin

    def _run(self, rows):
        """Drive _mail_admins with a stubbed query and captured mailer."""
        ctrl = controller.UserProfileController()

        active = [r for r in rows if r.state == 'active' and r.sysadmin]

        query = MagicMock()
        query.filter.return_value.all.return_value = active

        sent = []
        errors = []

        orig_session = controller.model.Session
        orig_mail = controller.mail_user
        orig_log = controller.log
        orig_tk = controller.tk

        try:
            controller.model.Session = MagicMock()
            controller.model.Session.query.return_value = query
            controller.mail_user = lambda recipient, **kw: sent.append(recipient.name)

            controller.log = MagicMock()
            controller.log.error = lambda msg, *a: errors.append(msg % a if a else msg)

            controller.tk = MagicMock()
            controller.tk.config.get.return_value = 'http://example.org'
            controller.tk._ = lambda s: s
            controller.tk.h.archive_manager_email.return_value = 'mgr@nris.no'

            ctrl._mail_admins({'fullname': 'Ada', 'name': 'ada'})
        finally:
            controller.model.Session = orig_session
            controller.mail_user = orig_mail
            controller.log = orig_log
            controller.tk = orig_tk

        return sent, errors

    def test_active_sysadmin_is_notified(self):
        sent, errors = self._run([self._admin('admin', 'a@nris.no')])
        self.assertEqual(['admin'], sent)
        self.assertEqual([], errors)

    def test_blank_email_is_reported_not_silent(self):
        sent, errors = self._run([self._admin('admin', '')])
        self.assertEqual([], sent)
        self.assertEqual(1, len(errors), 'empty-address case must be logged')

    def test_missing_email_is_reported_not_silent(self):
        sent, errors = self._run([self._admin('admin', None)])
        self.assertEqual([], sent)
        self.assertEqual(1, len(errors))

    def test_no_sysadmins_at_all_is_reported(self):
        sent, errors = self._run([])
        self.assertEqual([], sent)
        self.assertEqual(1, len(errors))

    def test_non_active_sysadmin_is_not_a_recipient(self):
        # A leftover deleted admin must not be counted as notified.
        sent, errors = self._run([self._admin('old', 'old@nris.no', state='deleted')])
        self.assertEqual([], sent)
        self.assertEqual(1, len(errors))

    def test_active_admin_still_notified_alongside_stale_rows(self):
        sent, errors = self._run([
            self._admin('old', 'old@nris.no', state='deleted'),
            self._admin('admin', 'a@nris.no'),
        ])
        self.assertEqual(['admin'], sent)
        self.assertEqual([], errors)

    def test_one_bad_address_does_not_block_other_admins(self):
        rows = [self._admin('a1', 'a1@nris.no'), self._admin('a2', 'a2@nris.no')]
        ctrl = controller.UserProfileController()
        query = MagicMock()
        query.filter.return_value.all.return_value = rows
        sent = []

        def flaky(recipient, **kw):
            if recipient.name == 'a1':
                raise Exception('bad address')
            sent.append(recipient.name)

        orig = (controller.model.Session, controller.mail_user, controller.tk)
        try:
            controller.model.Session = MagicMock()
            controller.model.Session.query.return_value = query
            controller.mail_user = flaky
            controller.tk = MagicMock()
            controller.tk.config.get.return_value = 'http://example.org'
            controller.tk._ = lambda s: s
            controller.tk.h.archive_manager_email.return_value = 'mgr@nris.no'
            ctrl._mail_admins({'fullname': 'Ada', 'name': 'ada'})
        finally:
            controller.model.Session, controller.mail_user, controller.tk = orig

        self.assertEqual(['a2'], sent, 'a2 must still receive the notification')


class NotifySubmissionContextTest(unittest.TestCase):
    """The notification worker must run inside a *request* context.

    _mail_user renders a template and both helpers translate strings.
    tk.render() goes through ckan.lib.base._allow_caching(), which reads g,
    session and request.environ, so an app context alone raised
    "Working outside of request context" in the worker thread and both
    emails were silently lost to the except blocks.
    """

    def test_worker_runs_in_a_request_context(self):
        import flask

        app = flask.Flask(__name__)
        app.secret_key = "test"

        seen = {}

        ctrl = controller.UserProfileController()

        def record(_user):
            # Mirrors what tk.render()/_allow_caching touch.
            seen["has_request"] = flask.has_request_context()
            flask.request.environ["__limit_cache_by_cookie__"] = True

        orig_tk, orig_flask = controller.tk, controller.flask
        try:
            controller.flask = flask
            controller.tk = MagicMock()
            controller.tk.config.get.return_value = "https://archive.example.org"

            ctrl._mail_user = record
            ctrl._mail_admins = lambda _d: None

            with app.test_request_context("/"):
                ctrl._notify_submission(MagicMock(), {"name": "ada"})

            # _notify_submission spawns a thread; wait for it.
            for t in threading.enumerate():
                if t is not threading.current_thread() and t.daemon is False:
                    t.join(timeout=5)
        finally:
            controller.tk, controller.flask = orig_tk, orig_flask

        self.assertTrue(
            seen.get("has_request"),
            "mail helpers must run inside a request context, not just an app context",
        )
