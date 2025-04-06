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
import yaml
import logging

from functools import partial
from ckan import plugins
import ckan.model as model
from ckan.common import g
from ckan.plugins import toolkit

from ckanext.oauth2 import oauth2
from ckanext.oauth2 import db
from ckanext.oauth2 import controller

log = logging.getLogger(__name__)

def _get_sso_options():
    yaml_file = toolkit.config.get(
        "ckan.oauth2.config_path",
        os.path.join(os.path.dirname(__file__), "..", "oauth_config.yaml"),
    )
    with open(yaml_file) as f:
        oauth_cofig = yaml.load(f, Loader=yaml.FullLoader)
        provider_list = []
        for provider in oauth_cofig["providers"]:
            provider_list.append(provider["name"])
    return provider_list


def _user_is_sso_user():
    user_name = toolkit.c.userobj.name
    user = db.UserToken.by_user_name(user_name=user_name)
    if user:
        return True
    return False


class OAuth2Plugin(plugins.SingletonPlugin):
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IBlueprint)
    plugins.implements(plugins.IConfigurer)

    def __init__(self, name=None):
        self.name = name
        log.debug("Initializing the OAuth2 plugin")

    # ITemplateHelpers
    def get_helpers(self):
        return {
            "sso_login_options": _get_sso_options,
            "user_is_sso_user": _user_is_sso_user,
        }

    def get_blueprint(self):
        return controller.get_blueprint()

    def identify(self):
        log.debug("Identifying the user")

        def _refresh_and_save_token(user_name):
            user = db.UserToken.by_user_name(user_name=user_name)
            oauth2helper = oauth2.OAuth2Helper(user.provider)
            new_token = oauth2helper.refresh_token(user_name)
            if new_token:
                toolkit.c.usertoken = new_token

        environ = toolkit.request.environ
        apikey = toolkit.request.headers.get(self.authorization_header, "")
        user_name = None

        if self.authorization_header == "authorization":
            if apikey.startswith("Bearer "):
                apikey = apikey[7:].strip()
            else:
                apikey = ""

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {"access_token": apikey}
                user = db.UserToken.by_user_token(token=token)
                try:
                    oauth2helper = oauth2.OAuth2Helper(user.provider)
                except AttributeError:
                    oauth2helper = oauth2.OAuth2Helper()
                user_name = oauth2helper.identify(token)
            except Exception:
                pass

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and "repoze.who.identity" in environ:
            user_name = environ["repoze.who.identity"]["repoze.who.userid"]
            log.info("User %s logged using session" % user_name)

        # If we have been able to log in the user (via API or Session)
        if user_name:
            g.user = user_name
            user = db.UserToken.by_user_name(user_name=user_name)
            try:
                oauth2helper = oauth2.OAuth2Helper(user.provider)
            except AttributeError:
                oauth2helper = oauth2.OAuth2Helper()
            toolkit.c.user = user_name
            toolkit.c.usertoken = oauth2helper.get_stored_token(user_name)
            toolkit.c.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            g.user = None
            log.warn("The user is currently not logged in.")

    def update_config(self, config):
        # Update our configuration
        self.register_url = os.environ.get(
            "CKAN_OAUTH2_REGISTER_URL", config.get("ckan.oauth2.register_url", None)
        )
        self.reset_url = os.environ.get(
            "CKAN_OAUTH2_RESET_URL", config.get("ckan.oauth2.reset_url", None)
        )
        self.edit_url = os.environ.get(
            "CKAN_OAUTH2_EDIT_URL", config.get("ckan.oauth2.edit_url", None)
        )
        self.authorization_header = os.environ.get(
            "CKAN_OAUTH2_AUTHORIZATION_HEADER",
            config.get("ckan.oauth2.authorization_header", "Authorization"),
        ).lower()

        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, "templates")
