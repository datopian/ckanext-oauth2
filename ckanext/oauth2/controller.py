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

import logging

from flask import Blueprint
from urllib.parse import urlparse

from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.plugins.toolkit as tk
from ckanext.oauth2 import constants

oauth2 = Blueprint("oauth2", __name__)

log = logging.getLogger(__name__)


def _get_previous_page(default_page):
    if "came_from" not in tk.request.params:
        came_from_url = tk.request.headers.get("Referer", default_page)
    else:
        came_from_url = tk.request.params.get("came_from", default_page)

    came_from_url_parsed = urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if (
        came_from_url_parsed.netloc != ""
        and came_from_url_parsed.netloc != tk.request.host
    ):
        came_from_url = default_page

    # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
    # he/she must be redirected to the dashboard
    pages = ["/", "/user/logged_out_redirect"]
    if came_from_url_parsed.path in pages:
        came_from_url = default_page

    return came_from_url


def login(provider):
    # Log in attemps are fired when the user is not logged in and they click
    # on the log in button

    # Get the page where the user was when the loggin attemp was fired
    # When the user is not logged in, he/she should be redirected to the dashboard when
    # the system cannot get the previous page
    from ckanext.oauth2 import oauth2

    oauth2helper = oauth2.OAuth2Helper(provider)
    came_from_url = _get_previous_page(constants.INITIAL_PAGE)
    auth_url = oauth2helper.challenge(came_from_url)
    return tk.redirect_to(auth_url)


def callback(provider):
    from ckanext.oauth2 import oauth2

    oauth2helper = oauth2.OAuth2Helper(provider)

    try:
        token = oauth2helper.get_token()
        user = oauth2helper.identify(token)

        if user.state == "rejected":
            helpers.flash_error(tk._("Your account has been rejected."))
            return tk.redirect_to("/")

        oauth2helper.login_user(user)
        oauth2helper.update_token(user.name, token)
        return oauth2helper.redirect_from_callback()

    except Exception as e:
        log.error("Error in OAuth2 callback: %s" % e)
        error_description = tk.request.args.get("error_description", None)
        if not error_description:
            for attr in ["message", "description", "error"]:
                if hasattr(e, attr) and getattr(e, attr):
                    error_description = getattr(e, attr)
                    break
            else:
                error_description = type(e).__name__

        redirect_url = oauth2.get_came_from(tk.request.params.get("state"))
        redirect_url = "/" if redirect_url == constants.INITIAL_PAGE else redirect_url
        log.error("Error in OAuth2 callback: %s" % e)
        helpers.flash_error(error_description)
        return tk.redirect_to(redirect_url)


oauth2.add_url_rule(
    "/oauth2/login/<provider>", "login", view_func=login, methods=["GET"]
)

oauth2.add_url_rule(
    "/oauth2/<provider>/callback", "callback", view_func=callback, methods=["GET"]
)


def get_blueprint():
    return [oauth2]
