# -*- coding: utf-8 -*-
#
# OAuth2 login-CSRF and open-redirect controls (SR0007564, issue #343).
#
# Covers the hardening that the older test_controller.py predates: the
# single-use session state nonce (generate_state / verify_state) and the
# _get_previous_page host allowlist that stops an external redirect target.

import unittest

from mock import MagicMock, patch
from parameterized import parameterized

from ckanext.oauth2 import oauth2, controller, constants


class FakeSession(dict):
    """A dict that also answers .save(), like CKAN's session object."""
    def save(self):
        self.saved = getattr(self, "saved", 0) + 1


class VerifyStateTest(unittest.TestCase):
    """The callback must accept only the exact nonce stored at challenge time,
    and only once (login-CSRF protection)."""

    def _run(self, stored, returned):
        sess = FakeSession()
        if stored is not None:
            sess[constants.STATE_SESSION_KEY] = stored
        with patch.object(oauth2, "session", sess):
            result = oauth2.verify_state(returned)
        return result, sess

    def test_matching_state_accepted_and_consumed(self):
        result, sess = self._run("nonce-abc", "nonce-abc")
        self.assertTrue(result)
        # single-use: the nonce is popped so a replay cannot reuse it
        self.assertNotIn(constants.STATE_SESSION_KEY, sess)

    def test_mismatched_state_rejected(self):
        result, _ = self._run("nonce-abc", "nonce-xyz")
        self.assertFalse(result)

    def test_missing_stored_state_rejected(self):
        result, _ = self._run(None, "nonce-abc")
        self.assertFalse(result)

    @parameterized.expand([("none", None), ("empty", "")])
    def test_missing_returned_state_rejected(self, _name, returned):
        result, _ = self._run("nonce-abc", returned)
        self.assertFalse(result)


class GenerateStateTest(unittest.TestCase):
    """generate_state must mint a random nonce, store it (and came_from)
    server-side, and never be predictable."""

    def test_stores_random_nonce_and_came_from(self):
        sess = FakeSession()
        with patch.object(oauth2, "session", sess):
            state = oauth2.generate_state("/dashboard")
        self.assertEqual(sess[constants.STATE_SESSION_KEY], state)
        self.assertEqual(sess[constants.CAME_FROM_SESSION_KEY], "/dashboard")
        self.assertGreaterEqual(len(state), 32)   # token_urlsafe(32)
        self.assertTrue(getattr(sess, "saved", 0) >= 1)

    def test_nonce_differs_each_call(self):
        seen = set()
        for _ in range(5):
            sess = FakeSession()
            with patch.object(oauth2, "session", sess):
                seen.add(oauth2.generate_state("/dashboard"))
        self.assertEqual(len(seen), 5)

    def test_verify_accepts_freshly_generated_state(self):
        sess = FakeSession()
        with patch.object(oauth2, "session", sess):
            state = oauth2.generate_state("/dashboard")
            self.assertTrue(oauth2.verify_state(state))


class PreviousPageRedirectTest(unittest.TestCase):
    """_get_previous_page is the open-redirect guard: a came_from pointing at a
    foreign host must fall back to the default page."""

    def _run(self, came_from, host="ckan.example.com", default="/dashboard"):
        req = MagicMock()
        req.host = host
        req.params = {"came_from": came_from} if came_from is not None else {}
        req.headers = {}
        with patch.object(controller, "tk") as tk:
            tk.request = req
            return controller._get_previous_page(default)

    def test_external_host_rejected(self):
        self.assertEqual(self._run("https://evil.example.com/steal"), "/dashboard")

    def test_protocol_relative_external_rejected(self):
        # //evil.com parses to netloc=evil.com — must also be rejected
        self.assertEqual(self._run("//evil.example.com/steal"), "/dashboard")

    def test_same_host_absolute_kept(self):
        url = "https://ckan.example.com/dataset/x"
        self.assertEqual(self._run(url), url)

    def test_relative_path_kept(self):
        self.assertEqual(self._run("/dataset/x"), "/dataset/x")

    @parameterized.expand([("home", "/"), ("logout", "/user/logged_out_redirect")])
    def test_home_and_logout_go_to_default(self, _name, path):
        self.assertEqual(self._run(path), "/dashboard")


if __name__ == "__main__":
    unittest.main()
