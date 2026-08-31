# -*- coding: utf-8 -*-
"""Auth functions restricting what a half-onboarded account may change.

The account gate in plugin.py is an after_request hook, so it only covers
browser navigation and cannot stop a direct API call. These wrap CKAN's own
auth so the same rules apply to user_update / user_patch however they are
reached - form, API token, or any future caller.
"""

import logging

import ckan.authz as authz
import ckan.plugins.toolkit as tk
import ckan.logic.auth as logic_auth
from ckan.logic.auth.update import user_update as core_user_update

log = logging.getLogger(__name__)

# Fields a user may never set on themselves. CKAN guards these with
# ignore_not_sysadmin, but that validator returns early whenever a caller
# passes ignore_auth, so they are checked here as well.
PROTECTED_FIELDS = ("sysadmin", "state", "plugin_extras")

# Account states in which the profile is under review and must not change.
LOCKED_ACCOUNT_STATES = ("pending",)


def _is_changed(user_obj, field, new_value):
    """True if `new_value` differs from what is stored on the user."""
    if user_obj is None:
        # Cannot compare, so treat any protected field as a change.
        return True

    current = getattr(user_obj, field, None)
    if field == "plugin_extras":
        # SQLAlchemy hands back None or a dict; normalise before comparing.
        return (current or {}) != (new_value or {})
    return current != new_value


def _locked_reason(user_obj):
    """Return a message if this account must not be edited, else None."""
    if user_obj is None:
        return None

    if user_obj.state == "rejected":
        return tk._("This account has been rejected and can no longer be updated.")

    extras = user_obj.plugin_extras or {}
    if extras.get("account_state") in LOCKED_ACCOUNT_STATES:
        return tk._("Your account is awaiting review and cannot be changed.")

    return None


def user_update(context, data_dict=None):
    data_dict = data_dict or {}

    result = core_user_update(context, data_dict)
    if not result.get("success"):
        return result

    requester = context.get("user")

    # Sysadmins administer these accounts: the approve/reject flow itself
    # needs to write state and plugin_extras.
    if requester and authz.is_sysadmin(requester):
        return result

    # Resolve the *target* of the update the same way core auth does.
    # context["auth_user_obj"] is the requester, which is not the same thing:
    # core only guarantees they match for non-sysadmins, and relying on that
    # coincidence here would be fragile.
    try:
        user_obj = logic_auth.get_user_object(context, data_dict)
    except tk.ObjectNotFound:
        return {"success": False, "msg": tk._("User not found")}

    # Compare against the stored value rather than just testing for presence:
    # user_patch merges user_show's output into the data_dict, so `state`
    # arrives on every patch and presence alone would reject valid calls.
    attempted = [
        field
        for field in PROTECTED_FIELDS
        if field in data_dict and _is_changed(user_obj, field, data_dict[field])
    ]
    if attempted:
        log.warning(
            "User %s attempted to set protected field(s): %s",
            requester,
            ", ".join(attempted),
        )
        return {
            "success": False,
            "msg": tk._("You are not allowed to change: {}").format(
                ", ".join(attempted)
            ),
        }

    reason = _locked_reason(user_obj)
    if reason:
        return {"success": False, "msg": reason}

    return result


def user_patch(context, data_dict=None):
    """user_patch delegates to user_update's auth; keep the rules identical."""
    return user_update(context, data_dict)
