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


import flask
from flask.views import MethodView
from flask import Blueprint, redirect
from urllib.parse import urlparse
import ckan.model as model
from ckan.lib.mailer import mail_user
from ckan.views.user import EditView
from ckan.views.api import _finish_ok
import ckan.logic as logic
import ckan.lib.navl.dictization_functions as dictization_functions
from sqlalchemy import cast, or_, and_, case, select
from sqlalchemy.dialects.postgresql import JSONB
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


def callback(provider):
    from ckanext.oauth2 import oauth2

    oauth2helper = oauth2.OAuth2Helper(provider)

    try:
        token = oauth2helper.get_token()
        user = oauth2helper.identify(token)

        if user.state == "rejected":
            return tk.redirect_to("oauth2.account_rejected")

        oauth2helper.login_user(user)
        oauth2helper.update_token(user.name, token)
        return oauth2helper.redirect_from_callback()

    except Exception as e:
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
        log.exception("Error in OAuth2 callback: %r", e)
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
            # No flash here: this runs in a worker thread with no request
            # session to write to, and the user has already been redirected.
            log.error("Error sending email to admin users: %s", e)

    def _mail_user(self, user):

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
            # Runs in a worker thread with no request session to flash into.
            log.error("Error sending email: %s", e)

    @staticmethod
    def _as_guest_flag(value):
        """Coerce the guest_user form value to a bool.

        tk.asbool raises on anything outside its true/false vocabulary, and
        an absent or empty field is normal here: clean_dict strips empty
        values, and older forms posted "". Treat those as "not a guest"
        rather than 500-ing.
        """
        if value is None or value == "":
            return False
        if isinstance(value, bool):
            return value
        try:
            return tk.asbool(value)
        except ValueError:
            log.warning("Unexpected guest_user value %r; treating as False", value)
            return False

    def _redirect_if_not_editable(self, user):
        """Stop a user editing their profile once it is out of their hands.

        The account gate runs as an after_request hook, so by the time it
        swaps in a redirect this view has already committed. A pending or
        rejected user must be turned away here, before any write happens.
        """
        state = (user.plugin_extras or {}).get("account_state")
        if state == "pending":
            return tk.redirect_to("oauth2.account_pending")
        if user.state == "rejected":
            return tk.redirect_to("oauth2.account_rejected")
        return None

    # Fields this form is allowed to set. Everything else is discarded:
    # the context below uses ignore_auth=True, which disables CKAN's
    # ignore_not_sysadmin validator, so an unfiltered dict would let a user
    # POST sysadmin/state/plugin_extras and escalate their own account.
    ALLOWED_FIELDS = frozenset([
        "fullname",
        "email",
        "about",
        "image_url",
        "image_upload",
        "clear_upload",
        "institution",
        "guest_user",
        "affiliation",
        "save",
    ])

    def _get_cleaned_data_dict(self):
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

        rejected = set(data_dict) - self.ALLOWED_FIELDS
        if rejected:
            log.warning(
                "Discarding unexpected profile fields from %s: %s",
                tk.current_user.name,
                ", ".join(sorted(rejected)),
            )

        return {k: v for k, v in data_dict.items() if k in self.ALLOWED_FIELDS}

    def _validate_data(self, data_dict, user):
        errors = {}

        if not data_dict.get("fullname"):
            errors["fullname"] = [tk._("Full name is required")]

        if not data_dict.get("guest_user") and not data_dict.get("institution"):
            errors["institution"] = [tk._("Institution name is required")]

        if not data_dict.get("email"):
            errors["email"] = [tk._("Email is required")]

        if data_dict.get("email"):
            existing_user = (
                model.Session.query(model.User)
                .filter(
                    model.User.email == data_dict.get("email"),
                    model.User.state.in_(["active", "pending", "incomplete"]),
                )
                .first()
            )

            if existing_user:
                if existing_user.state == "active" and existing_user.id != user.id:
                    errors["email"] = [
                        tk._("Account already exists with this email address")
                    ]
                elif existing_user.state == "pending" and existing_user.id != user.id:
                    errors["email"] = [
                        tk._(
                            "Another account already exists with this email address and is pending for approval"
                        )
                    ]

        return errors

    def _update_user_token(self, data_dict):
        user_name = data_dict.get("name")
        user_token = db.UserToken.by_user_name(user_name=user_name)
        if not user_token:
            user_token = db.UserToken(user_name=user_name)

        # Set on both paths: a first-time user has no token row yet, and
        # previously only the update branch persisted these fields.
        user_token.institution = data_dict.get("institution", "")
        user_token.guest = self._as_guest_flag(data_dict.get("guest_user"))

        model.Session.add(user_token)
        model.Session.commit()

    def get(self):
        if not tk.current_user.is_authenticated:
            return tk.abort(401, tk._("Unauthorized to visit this page"))

        user = model.User.get(tk.current_user.id)
        if not user:
            return tk.abort(404, tk._("User not found"))

        redirect = self._redirect_if_not_editable(user)
        if redirect:
            return redirect

        try:
            # User.get() is a classmethod lookup, not a dict accessor: the old
            # user.get("name") searched for a user literally named "name" and
            # returned None, so the saved institution never reached the form.
            user_token = db.UserToken.by_user_name(user_name=user.name)
            institution = user_token.institution if user_token else ""
            institution_title = ""
            if institution:
                group = model.Group.get(institution)
                if group:
                    institution_title = group.title or group.name

            extra_vars = {
                "data": {
                    "fullname": user.fullname,
                    "email": user.email,
                    "institution": institution,
                    "institution_title": institution_title,
                    "guest_user": user_token.guest if user_token else False,
                },
                "errors": {},
                "error_summary": {},
                "hide_masterhead": True,
            }

            return tk.render("user/account_update.html", extra_vars=extra_vars)
        except Exception as e:
            log.error("Error rendering account update form: %s", e)
            return tk.abort(500, tk._("Error loading your profile"))

    def post(self):
        context = self._prepare()

        if not tk.current_user.is_authenticated:
            return tk.abort(401, tk._("Unauthorized to visit this page"))

        user = model.User.get(tk.current_user.id)
        if not user:
            return tk.abort(404, tk._("User not found"))

        redirect = self._redirect_if_not_editable(user)
        if redirect:
            return redirect

        # Bound before the try so the error paths below can always re-render
        # the form with whatever the user typed.
        data_dict = {}

        try:
            data_dict = self._get_cleaned_data_dict()
            errors = self._validate_data(data_dict, user)
            if errors:
                raise tk.ValidationError(errors)

            user_token_dict = {
                "name": user.name,
                "guest_user": self._as_guest_flag(data_dict.get("guest_user")),
                "institution": data_dict.get("institution", ""),
            }

            data_dict["id"] = user.id
            data_dict.pop("guest_user", None)
            data_dict.pop("institution", None)
            data_dict["plugin_extras"] = {"account_state": "pending"}
            user_dict = tk.get_action("user_update")(context, data_dict)

            # Update user extras fields
            self._update_user_token(user_token_dict)

            # Notify off the request path: a slow or unreachable SMTP server
            # must not stall the redirect, and a failed notification must not
            # discard an account update that is already committed.
            self._notify_submission(user, user_dict)

            return tk.redirect_to("oauth2.account_pending")

        except tk.ValidationError as e:
            # Field-level problems: re-render with the messages next to the
            # inputs that caused them.
            return self._render_form(data_dict, e.error_dict, e.error_summary)

        except tk.NotAuthorized:
            # Not a form problem, and retrying will not help.
            return tk.abort(403, tk._("You are not allowed to update this profile"))

        except tk.ObjectNotFound:
            return tk.abort(404, tk._("User not found"))

        except Exception:
            # Genuinely unexpected: log the traceback and let CKAN show its
            # error page rather than implying the user did something wrong
            # or that retrying the same input would work.
            log.exception("Unexpected error updating profile for user %s", user.name)
            raise

    def _render_form(self, data_dict, errors, error_summary):
        return tk.render(
            "user/account_update.html",
            extra_vars={
                "data": data_dict,
                "errors": errors or {},
                "error_summary": error_summary or {},
                "hide_masterhead": True,
            },
        )

    def _notify_submission(self, user, user_dict):
        # The mail helpers read tk.config and render templates, so the worker
        # needs its own app context - the request one is gone by then.
        app = flask.current_app._get_current_object()

        def _send():
            with app.app_context():
                try:
                    self._mail_user(user)
                except Exception as e:
                    log.error("Error sending confirmation to user: %s", e)
                try:
                    self._mail_admins(user_dict)
                except Exception as e:
                    log.error("Error sending notification to admins: %s", e)

        threading.Thread(target=_send).start()


def account_rejected():
    """Explain a declined access request.

    The user is not logged in at this point (the OAuth2 callback stops before
    login_user), so this page shows no account details: the address is not
    put in the URL, where it would leak into logs and be caller-controlled.
    The administrator's reason is only sent by email, so it is not shown here.
    """
    try:
        contact_email = tk.h.archive_manager_email()
    except Exception:
        contact_email = ""

    extra_vars = {
        "contact_email": contact_email,
    }
    return tk.render("user/account_rejected.html", extra_vars=extra_vars)


def account_pending():
    if tk.current_user.is_authenticated:
        user = model.User.get(tk.current_user.id)

        # Check if user is pending with the plugin_extras
        if user.plugin_extras:
            account_state = user.plugin_extras.get("account_state", False)
            if account_state != "pending":
                return tk.abort(404, tk._("Not found"))

        # archive_manager_email() comes from ckanext-sigma2, which may not be
        # loaded; fall back to no address rather than breaking the page.
        try:
            contact_email = tk.h.archive_manager_email()
        except Exception:
            contact_email = ""

        extra_vars = {
            "user_id": user.id,
            "user_dict": user.as_dict(),
            "account_pending": True,
            "user_email": user.email,
            "contact_email": contact_email,
        }
        return tk.render("user/account_pending.html", extra_vars=extra_vars)


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
                db.UserToken.guest,
                model.User.plugin_extras,
            )
            .outerjoin(db.UserToken, model.User.name == db.UserToken.user_name)
            .filter(
                or_(
                    cast(model.User.plugin_extras, JSONB)["account_state"].astext.in_(
                        ["pending", "incomplete"]
                    ),
                    model.User.state == "rejected",
                )
            )
            .order_by(model.User.created)
            .all()
        )

        users = [
            dict(
                zip(user.keys(), user),
                state=(
                    user.plugin_extras.get("account_state", user.state)
                    if user.plugin_extras
                    else user.state
                ),
            )
            for user in users
        ]

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
        if not user:
            tk.abort(404, tk._("User not found"))

        if action == "approve":
            try:
                user.state = "active"
                user.plugin_extras = None
                model.Session.add(user)
                model.Session.commit()
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
            user.plugin_extras = None
            model.Session.add(user)
            model.Session.commit()
            self._mail_user(user, type="reject", message=message)

            # Delete user token if exists to allow user to register again
            user_token = db.UserToken.by_user_name(user_name=user.name)
            if user_token:
                model.Session.delete(user_token)
                model.Session.commit()

        tk.h.flash_success(
            tk._('User account "{}" successfully  {}.').format(
                user.fullname or user.email,
                "rejected" if action == "reject" else "approved",
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


def _reset_redirect():
    return tk.abort(404, tk._("Not found"))


def institution_autocomplete():
    query = tk.request.args.get("q", "")
    limit = tk.request.args.get("limit", 20)

    title_nb_subquery = (
        select([model.GroupExtra.value])
        .where(
            and_(
                model.GroupExtra.group_id == model.Group.id,
                model.GroupExtra.key == "title_nb",
                model.GroupExtra.value.ilike(f"%{query}%"),
            )
        )
        .limit(1)
        .as_scalar()
    )

    title_nb_case = case(
        [(title_nb_subquery != None, title_nb_subquery)],
        else_=model.Group.title,
    )

    q = model.Session.query(
        model.Group.id,
        model.Group.name,
        title_nb_case.label("title"),
        model.Group.image_url,
    ).filter(
        or_(
            model.Group.name.contains(query),
            model.Group.title.ilike("%" + query + "%"),
            model.Group.extras.any(
                and_(
                    model.GroupExtra.key == "title_nb",
                    model.GroupExtra.value.ilike(f"%{query}%"),
                )
            ),
        )
    )
    q = q.filter(model.Group.type == "institution")
    q = q.filter(model.Group.state == "active")
    q = q.order_by(model.Group.title)
    q = q.limit(limit)

    group_list = []
    for group in q.all():
        result_dict = {
            "id": group.id,
            "name": group.name,
            "title": group.title,
            "image_url": group.image_url,
        }
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
    "/user/account/update",
    view_func=UserProfileController.as_view(str("account_update")),
)

oauth2.add_url_rule("/user/account/pending", view_func=account_pending, methods=["GET"])
oauth2.add_url_rule(
    "/user/account/rejected", view_func=account_rejected, methods=["GET"]
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
