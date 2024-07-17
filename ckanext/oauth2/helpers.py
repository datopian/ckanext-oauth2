import os
import re
import yaml
import logging
from ckan import model

from ckan.plugins import toolkit

from ckanext.oauth2 import db

log = logging.getLogger(__name__)


def get_sso_options():
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


def user_is_sso_user():
    user_name = toolkit.c.userobj.name
    user = db.UserToken.by_user_name(user_name=user_name)
    if user:
        return True
    return False


def is_institution_exist(name_or_id):
    context = {
        "model": model,
        "session": model.Session,
    }

    def _slugify(string):
        string = string.lower()
        string = re.sub(r"\s+", "-", string)  # Replace spaces with dashes
        string = re.sub(
            r"[^\w\-]+", "", string
        )  # Remove non-word characters except dashes
        return string

    try:
        result = toolkit.get_action("group_show")(context, {"id": _slugify(name_or_id)})
    except toolkit.ObjectNotFound:
        return False
    return result
