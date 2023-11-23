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

from flask import Blueprint, redirect
from urllib.parse import urlparse

from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.plugins.toolkit as toolkit
from ckanext.oauth2 import constants

log = logging.getLogger(__name__)


def _get_previous_page(default_page):
    if "came_from" not in toolkit.request.params:
        came_from_url = toolkit.request.headers.get("Referer", default_page)
    else:
        came_from_url = toolkit.request.params.get("came_from", default_page)

    came_from_url_parsed = urlparse(came_from_url)

    # Avoid redirecting users to external hosts
    if (
        came_from_url_parsed.netloc != ""
        and came_from_url_parsed.netloc != toolkit.request.host
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
    return toolkit.redirect_to(auth_url)



def callback(provider):
    from ckanext.oauth2 import oauth2

    oauth2helper = oauth2.OAuth2Helper(provider)

    try:
        token = oauth2helper.get_token()
        user = oauth2helper.identify(token)
        oauth2helper.login_user(user)
        oauth2helper.update_token(user.name, token)
        return oauth2helper.redirect_from_callback()
    except Exception as e:
        print("============================")
        print(e)
        session.save()

        # If the callback is called with an error, we must show the message
        # error_description = toolkit.request.args.get("error_description", None)

        # if not error_description:
        #     if e.message:
        #         error_description = e.message
        #     elif hasattr(e, "description") and e.description:
        #         error_description = e.description
        #     elif hasattr(e, "error") and e.error:
        #         error_description = e.error
        #     else:
        #         error_description = type(e).__name__

        redirect_url = oauth2.get_came_from(toolkit.request.params.get("state"))
        redirect_url = "/" if redirect_url == constants.INITIAL_PAGE else redirect_url
        # helpers.flash_error(error_description)
        return toolkit.redirect_to(redirect_url)

oauth2 = Blueprint("oauth2", __name__)


def register_redirect():
    register_url = toolkit.config.get("ckanext.oauth2.register_url", None)
    return redirect(register_url)


def reset_redirect():
    reset_url = toolkit.config.get("ckanext.oauth2.reset_url", None)
    return redirect(reset_url)


def edit_redirect(user):
    edit_url = toolkit.config.get("ckanext.oauth2.edit_url", None)
    return redirect(edit_url.format(user=user))


oauth2.add_url_rule("/oauth2/login/<provider>", "login", view_func=login, methods=["GET"])

oauth2.add_url_rule("/oauth2/<provider>/callback", "callback", view_func=callback, methods=["GET"])
oauth2.add_url_rule(
    "/user/register", "redirect", view_func=register_redirect, methods=["GET"]
)
oauth2.add_url_rule(
    "/user/reset", "redirect", view_func=register_redirect, methods=["GET"]
)
oauth2.add_url_rule(
    "/user/edit/<user>", "redirect", view_func=register_redirect, methods=["GET"]
)


def get_blueprint():
    return [oauth2]
