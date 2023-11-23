# -*- coding: utf-8 -*-

# Copyright (c) 2014 CoNWeT Lab., Universidad Politécnica de Madrid

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

import logging
from flask import Blueprint, redirect

import ckan.lib.helpers as helpers
from ckan.plugins import toolkit

from ckanext.oauth2 import constants
from ckanext.oauth2 import oauth2

log = logging.getLogger(__name__)

oauth2 = Blueprint("oauth2", __name__)


def callback(self):
    try:
        oauth2helper = oauth2.OAuth2Helper()
        token = oauth2helper.get_token()
        user_name = oauth2helper.identify(token)
        oauth2helper.remember(user_name)
        oauth2helper.update_token(user_name, token)
        oauth2helper.redirect_from_callback()
    except Exception as e:
        # If the callback is called with an error, we must show the message
        error_description = toolkit.request.GET.get("error_description")
        if not error_description:
            if e.message:
                error_description = e.message
            elif hasattr(e, "description") and e.description:
                error_description = e.description
            elif hasattr(e, "error") and e.error:
                error_description = e.error
            else:
                error_description = type(e).__name__

        toolkit.response.status_int = 302
        redirect_url = oauth2.get_came_from(toolkit.request.params.get("state"))
        redirect_url = "/" if redirect_url == constants.INITIAL_PAGE else redirect_url
        toolkit.response.location = redirect_url
        helpers.flash_error(error_description)


def register_redirect():
    register_url = toolkit.config.get("ckanext.oauth2.register_url", None)
    return redirect(register_url)


def reset_redirect():
    reset_url = toolkit.config.get("ckanext.oauth2.reset_url", None)
    return redirect(reset_url)


def edit_redirect(user):
    edit_url = toolkit.config.get("ckanext.oauth2.edit_url", None)
    return redirect(edit_url.format(user=user))


oauth2.add_url_rule("/oauth2/callback", "callback", view_func=callback, methods=["GET"])
oauth2.add_url_rule("/user/register", "redirect", view_func=register_redirect, methods=["GET"])
oauth2.add_url_rule("/user/reset", "redirect", view_func=register_redirect, methods=["GET"])
oauth2.add_url_rule("/user/edit/<user>", "redirect", view_func=register_redirect, methods=["GET"])


def get_blueprint():
    return [oauth2]
