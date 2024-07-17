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

import re
import logging
import threading


from flask.views import MethodView
from flask import Blueprint, redirect
from urllib.parse import urlparse
import ckan.model as model
from ckan.lib.mailer import mail_user
from ckan.views.user import EditView
from ckan.views.api import _finish_ok
import ckan.logic as logic
import ckan.lib.navl.dictization_functions as dictization_functions
from sqlalchemy import or_

from ckan.common import session
import ckan.lib.helpers as helpers
import ckan.plugins.toolkit as tk

from ckanext.oauth2 import constants
from ckanext.oauth2 import db

log = logging.getLogger(__name__)


def _slugify(string):
    string = string.lower()
    string = re.sub(r"\s+", "-", string)  # Replace spaces with dashes
    string = re.sub(r"[^\w\-]+", "", string)  # Remove non-word characters except dashes
    return string


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


def __set_incomplete_registration_session(user):
    session["incomplete_registration"] = user.id


def _check_incomplete_registration(user_id):
    user = session.get("incomplete_registration", None)
    if user == user_id:
        return True
    return False


def _remove_incomplete_registration_session_if_exists():
    if "incomplete_registration" in session:
        session.pop("incomplete_registration", None)


def _login_and_redirect(oauth2helper, user, token):
    oauth2helper.login_user(user)
    oauth2helper.update_token(user.name, token)
    return oauth2helper.redirect_from_callback()


def callback(provider):
    from ckanext.oauth2 import oauth2

    oauth2helper = oauth2.OAuth2Helper(provider)

    try:
        token = oauth2helper.get_token()
        user = oauth2helper.identify(token)

        if tk.config.get(
            "ckanext.oauth2.profile_update_on_registration", False
        ) and not oauth2helper.get_stored_token(user.name):
            __set_incomplete_registration_session(user)
            return tk.redirect_to("oauth2.profile_update", user_id=user.id)

        if (
            tk.config.get("ckanext.oauth2.account_approval", False)
            and user.state == "pending"
        ):
            return tk.render(
                "user/account_pending.html",
                extra_vars={"user": user, "hide_masterhead": True},
            )

        if (
            tk.config.get("ckanext.oauth2.account_approval", False)
            and user.state == "rejected"
        ):
            helpers.flash_error(
                "Your account is reviewed and rejected. If you have any questions about your account, please contact the site administrator"
            )
            return tk.redirect_to("user.login")

        session["login_provider"] = provider
        _remove_incomplete_registration_session_if_exists()
        return _login_and_redirect(oauth2helper, user, token)

    except Exception as e:
        session.save()
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


class UserProfileController(MethodView):
    def _prepare(self):
        context = {
            "model": model,
            "session": model.Session,
            "ignore_auth": True,
            "keep_email": True,
        }
        return context

    def _mail_admins(self, user):
        account_user = user.get("fullname", user.get("name"))
        site_url = tk.config.get("ckan.site_url")
        institution = ""  # Not implemented yet
        archive_email = tk.h.archive_manager_email()

        subject = tk._("NIRD ARCHIVE: user access request")

        try:
            admins = model.Session.query(model.User).filter_by(sysadmin=True).all()
            for admin in admins:
                if admin.email:
                    body = f"""
                        <p>Dear {admin.fullname or admin.email},</p>
                        <p>The user: {account_user} from {institution} has submitted a request to use the archive.<br>
                        You can contact this user at <a href="mailto:{archive_email}">{archive_email}</a>for more details if required.<br>
                        To approve or decline this request please go to <a href="{site_url}/admin/account_review">{site_url}/admin/account_review</a>.</p>
                        <p>{archive_email}</p>
                    """
                    mail_user(
                        recipient=admin,
                        subject=subject,
                        body="",
                        body_html=body,
                    )
        except Exception as e:
            log.error("Error sending email: %s", e)
            tk.h.flash_error(tk._("Failed to send email to admin users"))

    def _mail_user(self, user_id):
        user = model.User.get(user_id)

        extra_vars = {
            "site_url": tk.config.get("ckan.site_url"),
            "site_title": tk.config.get("ckan.site_title"),
            "user_name": user.fullname if user.fullname else user.name,
            "signature": tk.h.archive_manager_email(),
        }
        subject = tk._(" NIRD Research Data Archive")
        body = tk.render("email/account_pending.txt", extra_vars=extra_vars)
        try:
            if user.email:
                mail_user(
                    recipient=user,
                    subject=subject,
                    body="",
                    body_html=body,
                )
        except Exception as e:
            log.error("Error sending email: %s", e)
            tk.h.flash_error(tk._("Failed to send email to user"))

    def get(self, user_id):
        context = self._prepare()
        try:
            if not _check_incomplete_registration(user_id):
                raise
            data_dict = {"id": user_id}
            user = tk.get_action("user_show")(context, data_dict)

            extra_vars = {
                "data": user,
                "errors": {},
                "error_summary": {},
                "hide_masterhead": True,
            }

            return tk.render("user/profie_update.html", extra_vars=extra_vars)
        except Exception as e:
            return tk.abort(404, "User not found")

    def post(self, user_id):
        context = self._prepare()
        try:
            if not _check_incomplete_registration(user_id):
                raise
            data_dict = dict(tk.request.form)

            data_dict["id"] = user_id
            include_fileds = [
                "id",
                "fullname",
                "email",
                "about",
                "image_url",
                "institution",
                "institution_email",
                "institution_url",
                "clear_upload",
                "save",
            ]
            # filter out fields that are only item  in include_fileds
            data_dict = {k: v for k, v in data_dict.items() if k in include_fileds}
            if not data_dict.get("fullname"):
                raise tk.ValidationError({"fullname": [tk._("Full name is required")]})

            if not data_dict.get("institution"):
                raise tk.ValidationError(
                    {"institution": [tk._("institution name is required")]}
                )
            data_dict["state"] = "pending"
            user_dict = tk.get_action("user_update")(context, data_dict)

            # Add user user token table, which means the user has completed profile update process
            user_token = db.UserToken.by_user_name(user_name=user_dict.get("name"))
            if not user_token:
                user_token = db.UserToken()
                user_token.user_name = user_dict.get("name")
                user_token.institution = {
                    "name": data_dict.get("institution", ""),
                    "email": data_dict.get("institution_email", ""),
                    "url": data_dict.get("institution_url", ""),
                }
                model.Session.add(user_token)
                model.Session.commit()

            # Now remove the incomplete registration session also
            # as the user has completed the profile update process already
            _remove_incomplete_registration_session_if_exists()

            self._mail_user(user_dict.get("id"))

            thread = threading.Thread(target=self._mail_admins, args=(user_dict,))
            thread.start()

            return tk.render(
                "user/account_pending.html",
                extra_vars={"user": user_dict, "hide_masterhead": True},
            )

        except tk.ValidationError as e:
            errors = e.error_dict
            error_summary = e.error_summary
            extra_vars = {
                "data": data_dict,
                "errors": errors,
                "error_summary": error_summary,
            }
            return tk.render("user/profie_update.html", extra_vars=extra_vars)


class AccountReview(MethodView):
    def __prepare(self):
        context = {"model": model, "session": model.Session, "user": tk.c.user}
        try:
            tk.check_access("sysadmin", context)
        except tk.NotAuthorized:
            tk.abort(401, tk._("Unauthorized to visit this page"))
        return context

    def _mail_user(self, user, type, message=None):
        if message:
            f"""
            <strong>Message from Archive Manager:</strong>
            <blockquote style="background-color: #f2f2f2; padding: 4px; border-left: 4px solid #bc9191;">
                <p>{message}</p>
            </blockquote>
            """
        else:
            message = ""

        extra_vars = {
            "site_url": tk.config.get("ckan.site_url"),
            "site_title": tk.config.get("ckan.site_title"),
            "user_name": user.fullname if user.fullname else user.name,
            "signature": tk.h.archive_manager_email(),
            "message": message,
        }

        if type == "reject":
            subject = tk._("NIRD ARCHIVE: Declined to use the archive")
            body = tk.render("email/account_rejected.txt", extra_vars=extra_vars)
        elif type == "approve":
            subject = tk._("NIRD ARCHIVE: Approved to use the archive")
            body = tk.render("email/account_approved.txt", extra_vars=extra_vars)
        try:
            if user.email:
                mail_user(
                    recipient=user,
                    subject=subject,
                    body="",
                    body_html=body,
                )
        except Exception as e:
            log.error("Error sending email: %s", e)
            tk.h.flash_error(tk._("Failed to send email to user"))

    def get(self):
        context = self.__prepare()
        users = (
            model.Session.query(
                model.User.id,
                model.User.name,
                model.User.fullname,
                model.User.email,
                model.User.state,
                model.User.about,
                model.User.created,
                db.UserToken.institution,
            )
            .outerjoin(db.UserToken, model.User.name == db.UserToken.user_name)
            .filter(
                model.User.state.in_(["pending", "rejected", "active"]),
            )
            .order_by(model.User.created)
            .all()
        )

        users = [dict(zip(user.keys(), user)) for user in users]

        extra_vars = {
            "users": users,
            "pending_count": len(users),
            "pending_count_plural": len(users) > 1,
        }
        return tk.render("admin/account_review.html", extra_vars=extra_vars)

    def post(self):
        context = self.__prepare()
        user_id = tk.request.form.get("id")
        action = tk.request.form.get("action")
        message = tk.request.form.get("message")
        user = model.User.get(user_id)

        user_extra = db.UserToken.by_user_name(user_name=user.name)

        if not user:
            tk.abort(404, tk._("User not found"))

        if action == "approve":
            try:
                user.state = "active"
                # Create an institution if not already exists
                if not tk.h.is_institution_exist(user_extra.institution.get("name")):
                    log.info(
                        "Creating institution: %s", user_extra.institution.get("name")
                    )
                    tk.config.get("ckan.site_url")

                    institution_dict = {
                        "name": _slugify(user_extra.institution.get("name")),
                        "title": user_extra.institution.get("name"),
                        "description": user_extra.institution.get("name"),
                        "website": user_extra.institution.get("url"),
                        "email": user_extra.institution.get("email"),
                        "state": "active",
                        "type": "institution",
                    }

                    tk.get_action("group_create")(context, institution_dict)

                # add user as member of the group
                log.info(
                    "Adding user to institution: %s",
                    user_extra.institution.get("name"),
                )
                tk.get_action("group_member_create")(
                    context,
                    {
                        "id": _slugify(user_extra.institution.get("name")),
                        "username": user.name,
                        "role": "member",
                    },
                )
            except Exception as e:
                log.error("Error approving user: %s", e)
                tk.h.flash_error(
                    tk._(
                        "Failed to approve user, please contact the site administrator"
                    )
                )

            self._mail_user(user, type="approve")
        elif action == "reject":
            user.state = "rejected"
            self._mail_user(user, type="reject", message=message)

            tk.get_action("user_update")(
                context, {"id": user_id, "state": "rejected", "email": user.email}
            )

            # Delete user token if exists to allow user to register again
            user_token = db.UserToken.by_user_name(user_name=user.name)
            if user_token:
                model.Session.delete(user_token)
                model.Session.commit()

        tk.h.flash_success(
            tk._('User account "{}" successfully  {}.').format(
                user.fullname or user.email,
                "rejected" if action == "reject" else "Approved",
            )
        )
        return tk.redirect_to("oauth2.account_review")


class UserEditView(EditView):
    def __init__(self) -> None:
        super().__init__()

    def post(self, id):
        # This needed to be overrided as sysadmin cannot
        # edit user without providing password
        context, id = self._prepare(id)
        if tk.c.userobj.sysadmin:
            if not context["save"]:
                return self.get(id)

            try:
                data_dict = logic.clean_dict(
                    dictization_functions.unflatten(
                        logic.tuplize_dict(logic.parse_params(tk.request.form))
                    )
                )
                data_dict.update(
                    logic.clean_dict(
                        dictization_functions.unflatten(
                            logic.tuplize_dict(logic.parse_params(tk.request.files))
                        )
                    )
                )

            except dictization_functions.DataError:
                tk.abort(400, tk._("Integrity Error"))
            data_dict.setdefault("activity_streams_email_notifications", False)

            data_dict["id"] = id
            # deleted user can be reactivated by sysadmin on WEB-UI
            is_deleted = False
            if tk.asbool(data_dict.get("activate_user", False)):
                user_dict = logic.get_action("user_show")(context, {"id": id})
                # set the flag so if validation error happens we will
                # change back the user state to deleted
                is_deleted = user_dict.get("state") == "deleted"
                # if activate_user is checked, change the user's state to active
                data_dict["state"] = "active"
                # pop the value as we don't want to send it for
                # validation on user_update
                data_dict.pop("activate_user")
            # we need this comparison when sysadmin edits a user,
            # this will return True
            # and we can utilize it for later use.

            # common users can edit their own profiles without providing
            # password, but if they want to change
            # their old password with new one... old password must be provided..
            # so we are checking here if password1
            # and password2 are filled so we can enter the validation process.
            # when sysadmins edits a user he MUST provide sysadmin password.
            # We are recognizing sysadmin user
            # by email_changed variable.. this returns True
            # and we are entering the validation.

            try:
                user = logic.get_action("user_update")(context, data_dict)
            except tk.NotAuthorized:
                tk.abort(403, tk._("Unauthorized to edit user %s") % id)
            except tk.ObjectNotFound:
                tk.abort(404, tk._("User not found"))
            except tk.ValidationError as e:
                errors = e.error_dict
                error_summary = e.error_summary
                # the user state was deleted, we are trying to reactivate it but
                # validation error happens so we want to change back the state
                # to deleted, as it was before
                if is_deleted and data_dict.get("state") == "active":
                    data_dict["state"] = "deleted"
                return self.get(id, data_dict, errors, error_summary)

            tk.h.flash_success(tk._("Profile updated"))
            resp = tk.h.redirect_to("user.read", id=user["name"])
            return resp
        else:
            return super().post(id)


def _reset_redirect():
    return tk.abort(404, tk._("Not found"))


def institution_autocomplete():
    q = tk.request.args.get("q", "")
    limit = tk.request.args.get("limit", 20)
    q = model.Session.query(model.Group).filter(
        or_(
            model.Group.name.contains(q),
            model.Group.title.ilike("%" + q + "%"),
        )
    )
    q = q.filter(model.Group.type == "institution")
    q = q.filter(model.Group.state == "active")
    q.order_by(model.Group.title)

    q = q.limit(limit)

    group_list = []
    for group in q.all():
        result_dict = {}
        for k in ["id", "name", "title", "image_url"]:
            result_dict[k] = getattr(group, k)
        group_list.append(result_dict)

    return _finish_ok(group_list)


oauth2 = Blueprint("oauth2", __name__)

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

oauth2.add_url_rule(
    "/admin/account_review", view_func=AccountReview.as_view("account_review")
)


_edit_view = UserEditView.as_view(str("edit"))


oauth2.add_url_rule("/user/edit", view_func=_edit_view)
oauth2.add_url_rule("/user/edit/<id>", view_func=_edit_view)
oauth2.add_url_rule("/user/reset", view_func=_reset_redirect)

oauth2.add_url_rule(
    "/api/3/util/institution/autocomplete", view_func=institution_autocomplete
)


def get_blueprint():
    return [oauth2]
