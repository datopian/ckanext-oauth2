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

from __future__ import unicode_literals

import os
import re
import yaml
import base64
import random
import json
import logging
import requests
import six
import jwt
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import InsecureTransportError
from six.moves.urllib.parse import urljoin, urlparse, urlunparse
from base64 import b64encode, b64decode

import ckan.model as model
from ckan.plugins import toolkit
from ckan.common import login_user

from ckanext.oauth2 import constants
from ckanext.oauth2 import db
from ckanext.oauth2.helpers import load_oauth2_config

log = logging.getLogger(__name__)


def generate_state(url):
    return b64encode(bytes(json.dumps({constants.CAME_FROM_FIELD: url}), "utf-8"))


def get_came_from(state):
    if state is None:
        return "/"
    return json.loads(b64decode(state)).get(constants.CAME_FROM_FIELD, "/")


REQUIRED_CONF = (
    "authorization_endpoint",
    "token_endpoint",
    "client_id",
    "client_secret",
    "profile_api_url",
    "profile_api_user_field",
    "profile_api_mail_field",
)


class OAuth2Helper(object):
    def __init__(self, provider="github"):
        self.provider = provider
        self.oauth_config = load_oauth2_config()
        self.set_provider_config()

    def set_provider_config(self):
        if self.oauth_config is None:
            raise ValueError("Failed to load configuration.")

        provider = list(
            filter(
                lambda x: x["name"].lower() == self.provider.lower(),
                self.oauth_config["providers"],
            )
        )[0]

        self.client_id = provider["client_id"]
        self.client_secret = provider["client_secret"]
        self.authorization_endpoint = provider["authorization_endpoint"]
        self.token_endpoint = provider["token_endpoint"]
        self.profile_api_url = provider["profile_api_url"]
        self.profile_api_user_field = provider.get("profile_api_user_field")
        self.profile_api_first_name_field = provider.get("profile_api_first_name_field")
        self.profile_api_last_name_field = provider.get("profile_api_last_name_field")
        self.profile_api_mail_field = provider["profile_api_mail_field"]
        self.scope = "%s" % provider["scope"]
        self.profile_api_fullname_field = provider.get(
            "profile_api_fullname_field", None
        )
        self.profile_api_groupmembership_field = provider.get(
            "profile_api_groupmembership_field", None
        )
        self.sysadmin_group_name = provider.get("sysadmin_group_name", None)

        self.verify_https = os.environ.get("OAUTHLIB_INSECURE_TRANSPORT", "") == ""
        if self.verify_https and os.environ.get("REQUESTS_CA_BUNDLE", "").strip() != "":
            self.verify_https = os.environ["REQUESTS_CA_BUNDLE"].strip()

        self.jwt_enable = six.text_type(
            os.environ.get(
                "CKAN_OAUTH2_JWT_ENABLE",
                toolkit.config.get("ckan.oauth2.jwt.enable", ""),
            )
        ).strip().lower() in ("true", "1", "on")
        self.legacy_idm = six.text_type(
            os.environ.get(
                "CKAN_OAUTH2_LEGACY_IDM",
                toolkit.config.get("ckan.oauth2.legacy_idm", ""),
            )
        ).strip().lower() in ("true", "1", "on")
        self.rememberer_name = six.text_type(
            os.environ.get(
                "CKAN_OAUTH2_REMEMBER_NAME",
                toolkit.config.get("ckan.oauth2.rememberer_name", "auth_tkt"),
            )
        ).strip()
        self.redirect_uri = urljoin(
            urljoin(
                toolkit.config.get("ckan.site_url", "http://localhost:5000"),
                toolkit.config.get("ckan.root_path"),
            ),
            "/oauth2/%s/callback" % self.provider,
        )

        missing = [key for key in REQUIRED_CONF if getattr(self, key, "") == ""]
        if missing:
            raise ValueError("Missing required oauth2 conf: %s" % ", ".join(missing))
        elif self.scope == "":
            self.scope = None

    def challenge(self, came_from_url):
        # This function is called by the log in function when the user is not logged in
        state = generate_state(came_from_url)
        oauth = OAuth2Session(
            self.client_id,
            redirect_uri=self.redirect_uri,
            scope=self.scope,
            state=state,
        )
        auth_url, _ = oauth.authorization_url(
            self.authorization_endpoint, prompt="consent"
        )
        log.debug("Challenge: Redirecting challenge to page {0}".format(auth_url))
        return auth_url

    def get_token(self):
        oauth = OAuth2Session(
            self.client_id, redirect_uri=self.redirect_uri, scope=self.scope
        )

        # Just because of FIWARE Authentication
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        if self.legacy_idm:
            # This is only required for Keyrock v6 and v5
            headers["Authorization"] = "Basic %s" % base64.urlsafe_b64encode(
                "%s:%s" % (self.client_id, self.client_secret)
            )

        try:
            token = oauth.fetch_token(
                self.token_endpoint,
                headers=headers,
                client_secret=self.client_secret,
                authorization_response=toolkit.request.url,
                verify=self.verify_https,
            )
        except requests.exceptions.SSLError as e:
            # TODO search a better way to detect invalid certificates
            if "verify failed" in six.text_type(e):
                raise InsecureTransportError()
            else:
                raise
        except Exception as e:
            raise e
        return token

    def identify(self, token):
        if self.jwt_enable:
            access_token = bytes(token["access_token"])
            user_data = jwt.decode(access_token, verify=False)
            user = self.user_json(user_data)
        else:
            try:
                if self.legacy_idm:
                    profile_response = requests.get(
                        self.profile_api_url
                        + "?access_token=%s" % token["access_token"],
                        verify=True,
                    )
                else:
                    oauth = OAuth2Session(self.client_id, token=token)
                    profile_response = oauth.get(self.profile_api_url, verify=True)

            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise
            except Exception as e:
                raise e

            # TODO: Remove this later on production
            logging.info(profile_response.json())

            # Token can be invalid
            if not profile_response.ok:
                error = profile_response.json()
                if error.get("error", "") == "invalid_token":
                    raise ValueError(error.get("error_description"))
                else:
                    profile_response.raise_for_status()
            else:
                user_data = profile_response.json()
                user = self.user_json(user_data)

        # Save the user in the database
        model.Session.add(user)
        model.Session.commit()
        model.Session.remove()

        return user

    def user_json(self, user_data):
        # Github provides email in list format
        if self.profile_api_url.startswith("https://api.github.com"):
            email = [e["email"] for e in user_data if e["primary"] == True][0]
        else:
            email = user_data.get(self.profile_api_mail_field)
        profile_update_on_registration = toolkit.config.get(
            "ckanext.oauth2.profile_update_on_registration", False
        )
        # In CKAN can exists more than one user associated with the same email
        # Some providers, like Google and FIWARE only allows one account per email
        user = None
        if email:
            existing_user = model.User.by_email(email)
            if existing_user:
                existing_user.state = (
                    "active" if existing_user.state == "active" else existing_user.state
                )
                user = existing_user
            else:
                user = model.User()
                user.email = email
                name = email.partition("@")[0]
                name = re.sub(r"\W", "_", name)
                is_name_available = model.User.check_name_available(name)
                user.state = "pending" if profile_update_on_registration else "active"
                user.name = (
                    name if is_name_available else name + "%s" % random.randint(10, 20)
                )
        else:
            # if no email is provided, use the user_id or other unique field
            user_id_or_name = user_data.get(self.profile_api_user_field)
            existing_user = model.User.get(user_id_or_name)
            if existing_user:
                existing_user.state = (
                    "active" if existing_user.state == "active" else existing_user.state
                )
                user = existing_user
            else:
                user = model.User()
                user.email = None
                user.state = "pending" if profile_update_on_registration else "active"
                is_name_available = model.User.check_name_available(user_id_or_name)
                user.name = user_id_or_name

        def _set_fullname(user_data, fullname_field, first_name_field, last_name_field):
            if fullname_field in user_data:
                return user_data.get(fullname_field)
            elif first_name_field in user_data and last_name_field in user_data:
                return f"{user_data.get(first_name_field, '')} {user_data.get(last_name_field, '')}".strip()
            return None

        # Check and set if user have full name or first and last name
        if not user.fullname:
            fullname_field = self.profile_api_fullname_field
            first_name_field = self.profile_api_first_name_field
            last_name_field = self.profile_api_last_name_field
            user.fullname = _set_fullname(
                user_data, fullname_field, first_name_field, last_name_field
            )
        return user

    def login_user(self, user):
        """
        Remember the authenticated identity.

        This method simply delegates to another IIdentifier plugin if configured.
        """
        login_user(user)

    def redirect_from_callback(self):
        """Redirect to the callback URL after a successful authentication."""
        state = toolkit.request.params.get("state")
        came_from = get_came_from(state)

        if urlparse(came_from).path == "/user/login":
            came_from = urlunparse(
                urlparse(came_from)._replace(path=constants.INITIAL_PAGE)
            )
            return toolkit.redirect_to(came_from)
        else:
            return came_from

    def get_stored_token(self, user_name):
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if user_token:
            return {
                "access_token": user_token.access_token,
                "refresh_token": user_token.refresh_token,
                "expires_in": user_token.expires_in,
                "token_type": user_token.token_type,
            }
        return None

    def update_token(self, user_name, token):
        user_token = db.UserToken.by_user_name(user_name=user_name)
        # Create the user if it does not exist
        if not user_token:
            user_token = db.UserToken()
            user_token.user_name = user_name
        # Save the new token
        user_token.access_token = token["access_token"]
        user_token.token_type = token["token_type"]
        user_token.refresh_token = token.get("refresh_token")
        user_token.expires_in = token.get("expires_in")
        user_token.provider = self.provider

        if "expires_in" in token:
            user_token.expires_in = token["expires_in"]
        else:
            try:
                access_token = jwt.decode(user_token.access_token, verify=False)
                user_token.expires_in = access_token["exp"] - access_token["iat"]
            except jwt.exceptions.DecodeError as e:
                user_token.expires_in = 3599
        model.Session.add(user_token)
        model.Session.commit()

    def refresh_token(self, user_name):
        token = self.get_stored_token(user_name)
        if token:
            client = OAuth2Session(self.client_id, token=token, scope=self.scope)
            try:
                token = client.refresh_token(
                    self.token_endpoint,
                    client_secret=self.client_secret,
                    client_id=self.client_id,
                    verify=self.verify_https,
                )
            except requests.exceptions.SSLError as e:
                # TODO search a better way to detect invalid certificates
                if "verify failed" in six.text_type(e):
                    raise InsecureTransportError()
                else:
                    raise
            except:
                log.error("Error refreshing token for user %s" % user_name)
                raise
            self.update_token(user_name, token)
            log.info("Token for user %s has been updated properly" % user_name)
            return token
        else:
            log.warn("User %s has no refresh token" % user_name)
