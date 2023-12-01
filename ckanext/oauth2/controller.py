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
from flask.views import MethodView
from flask import Blueprint, redirect
from urllib.parse import urlparse
import ckan.model as model

from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.plugins.toolkit as toolkit
from ckanext.oauth2 import constants
from ckanext.oauth2 import db

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


def __set_incomplete_registration_session(user, provider):
    session["incomplete_registration"] = {
        "id": user.id,
        "provider": provider,
    }


def __remove_incomplete_registration_session_if_exists():
    if "incomplete_registration" in session:
        session.pop("incomplete_registration", None)


def __login_and_redirect(oauth2helper, user, token):
    oauth2helper.login_user(user)
    oauth2helper.update_token(user.name, token)
    return oauth2helper.redirect_from_callback()


def callback(provider):
    from ckanext.oauth2 import oauth2

    oauth2helper = oauth2.OAuth2Helper(provider)

    try:
        token = oauth2helper.get_token()
        user = oauth2helper.identify(token)

        if toolkit.config.get(
            "ckanext.oauth2.profile_update_on_registration", False
        ) and not oauth2helper.get_stored_token(user.name):
            __set_incomplete_registration_session(user, provider)
            return toolkit.redirect_to("oauth2.profile_update", user_id=user.id)

        if (
            toolkit.config.get("ckanext.oauth2.account_approval", False)
            and user.state == "pending"
        ):
            __set_incomplete_registration_session(user, provider)
            return toolkit.redirect_to("oauth2.user_pending", user_id=user.id)

        __remove_incomplete_registration_session_if_exists()
        return __login_and_redirect(oauth2helper, user, token)

    except Exception as e:
        session.save()
        error_description = toolkit.request.args.get("error_description", None)
        if not error_description:
            for attr in ["message", "description", "error"]:
                if hasattr(e, attr) and getattr(e, attr):
                    error_description = getattr(e, attr)
                    break
            else:
                error_description = type(e).__name__

        redirect_url = oauth2.get_came_from(toolkit.request.params.get("state"))
        redirect_url = "/" if redirect_url == constants.INITIAL_PAGE else redirect_url
        log.error("Error in OAuth2 callback: %s" % e)
        helpers.flash_error(error_description)
        return toolkit.redirect_to(redirect_url)


class UserProfileController(MethodView):
    def _prepare(self):
        context = {
            "model": model,
            "session": model.Session,
            "ignore_auth": True,
            "keep_email": True,
        }
        return context

    def get(self, user_id):
        context = self._prepare()
        try:
            if not toolkit.h.incomplete_registration(user_id):
                raise
            data_dict = {"id": user_id}
            user = toolkit.get_action("user_show")(context, data_dict)
            extra_vars = {
                "data": user,
                "errors": {},
                "error_summary": {},
                "hide_masterhead": True,
            }
            return toolkit.render("user/profie_update.html", extra_vars=extra_vars)
        except Exception as e:
            return toolkit.abort(404, "User not found")

    def post(self, user_id):
        context = self._prepare()
        try:
            if not toolkit.h.incomplete_registration(user_id):
                raise
            data_dict = dict(toolkit.request.form)
            data_dict["id"] = user_id
            include_fileds = [
                "id",
                "fullname",
                "email",
                "about",
                "image_url",
                "clear_upload",
                "save",
            ]
            # filter out fields that are only item  in include_fileds
            data_dict = {k: v for k, v in data_dict.items() if k in include_fileds}

            return_dict = toolkit.get_action("user_update")(context, data_dict)

            # Add user user token table, which means the user has completed profile update process
            user_token = db.UserToken.by_user_name(user_name=return_dict.get("name"))
            if not user_token:
                user_token = db.UserToken()
                user_token.user_name = return_dict.get("name")
                model.Session.add(user_token)
                model.Session.commit()

            return toolkit.redirect_to("oauth2.user_pending", user_id=user_id)
        except toolkit.ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            extra_vars = {
                "data": data_dict,
                "errors": errors,
                "error_summary": error_summary,
            }
            return toolkit.render("user/profie_update.html", extra_vars=extra_vars)


oauth2 = Blueprint("oauth2", __name__)


def user_pending(user_id):
    try:
        if not toolkit.h.incomplete_registration(user_id):
            raise
        user = toolkit.get_action("user_show")({"ignore_auth": True}, {"id": user_id})
        return toolkit.render(
            "user/account_pending.html",
            extra_vars={"user": user, "hide_masterhead": True},
        )
    except Exception as e:
        return toolkit.abort(404, "User not found")


oauth2.add_url_rule(
    "/oauth2/login/<provider>", "login", view_func=login, methods=["GET"]
)

oauth2.add_url_rule(
    "/oauth2/<provider>/callback", "callback", view_func=callback, methods=["GET"]
)


oauth2.add_url_rule(
    "/user/edit/profile/<user_id>",
    view_func=UserProfileController.as_view(str("profile_update")),
)

oauth2.add_url_rule("/user/account/<user_id>", view_func=user_pending, methods=["GET"])


def get_blueprint():
    return [oauth2]
