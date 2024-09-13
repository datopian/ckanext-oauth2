import os
import re
import yaml
import logging
from ckan import model
import json
from ckan.plugins import toolkit

from ckanext.oauth2 import db

log = logging.getLogger(__name__)


def load_oauth2_config():
    config_file_path = toolkit.config.get("ckan.oauth2.config_file")
    config_json = toolkit.config.get("ckan.oauth2.config_json")

    if config_json:
        return json.loads(config_json)
    elif config_file_path:
        file_extension = os.path.splitext(config_file_path)[1].lower()
        with open(config_file_path) as f:
            if file_extension == ".json":
                return json.load(f)
            elif file_extension in [".yaml", ".yml"]:
                return yaml.load(f, Loader=yaml.FullLoader)
            else:
                raise ValueError(
                    "Unsupported file format. Please provide a JSON or YAML file."
                )
    else:
        raise ValueError(
            "No valid configuration found. Please set either 'ckan.oauth2.config_file' or 'ckan.oauth2.config_json'."
        )


def get_sso_options():
    config = load_oauth2_config()
    provider_list = [provider["name"] for provider in config["providers"]]
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
