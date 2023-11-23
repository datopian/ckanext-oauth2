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

from __future__ import unicode_literals

from ckanext.oauth2 import constants 
import logging
from ckanext.oauth2 import oauth2
from ckanext.oauth2 import controller

from functools import partial
from ckan import plugins
from ckan.common import session
from ckan.plugins import toolkit

from ckan.common import config

from urllib.parse import urlparse

log = logging.getLogger(__name__)


def _no_permissions(context, msg):
    user = context['user']
    return {'success': False, 'msg': msg.format(user=user)}


@toolkit.auth_sysadmins_check
def user_create(context, data_dict):
    msg = toolkit._('Users cannot be created.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_update(context, data_dict):
    msg = toolkit._('Users cannot be edited.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def user_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


@toolkit.auth_sysadmins_check
def request_reset(context, data_dict):
    msg = toolkit._('Users cannot reset passwords.')
    return _no_permissions(context, msg)


class OAuth2Plugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IConfigurable)
    plugins.implements(plugins.IAuthenticator, inherit=True)
    plugins.implements(plugins.IAuthFunctions, inherit=True)
    plugins.implements(plugins.IBlueprint)

    def update_config(self, config):
        # Add this plugin's templates dir to CKAN's extra_template_paths, so
        # that CKAN will use this plugin's custom templates.
        plugins.toolkit.add_template_directory(config, 'templates')
    
    # IConfigurable
    def configure(self, config):
        # Certain config options must exists for the plugin to work. Raise an
        # exception if they're missing.
        missing_config = "{0} is not configured. Please amend your .ini file."
        config_options = (
            'ckanext.oauth2.authorization_endpoint',
            'ckanext.oauth2.token_endpoint',
            'ckanext.oauth2.profile_api_url',
            'ckanext.oauth2.client_id',
            'ckanext.oauth2.client_secret',
            'ckanext.oauth2.scope',
            'ckanext.oauth2.rememberer_name',
            'ckanext.oauth2.profile_api_user_field',
            'ckanext.oauth2.profile_api_fullname_field',
            'ckanext.oauth2.profile_api_mail_field',
            'ckanext.oauth2.profile_api_groupmembership_field',
            'ckanext.oauth2.sysadmin_group_name'
        )
    
    def get_blueprint(self):
        return controller.get_blueprint()
        
    def identify(self):
        log.debug('identify')

        oauth2helper = oauth2.OAuth2Helper()

        authorization_header = config.get('ckanext.oauth2.authorization_header', 'Authorization')

        # Create session if it does not exist. Workaround to show flash messages
        session.save()

        def _refresh_and_save_token(user_name):
            new_token = oauth2helper.refresh_token(user_name)
            if new_token:
                toolkit.c.usertoken = new_token

        environ = toolkit.request.environ
        apikey = toolkit.request.headers.get(authorization_header, '')
        user_name = None

        # This API Key is not the one of CKAN, it's the one provided by the OAuth2 Service
        if apikey:
            try:
                token = {'access_token': apikey}
                user_name = oauth2helper.identify(token)
            except Exception:
                pass

        # If the authentication via API fails, we can still log in the user using session.
        if user_name is None and 'repoze.who.identity' in environ:
            user_name = environ['repoze.who.identity']['repoze.who.userid']
            log.info('User %s logged using session' % user_name)

        # If we have been able to log in the user (via API or Session)
        if user_name:
            toolkit.c.user = user_name
            toolkit.c.usertoken = oauth2helper.get_stored_token(user_name)
            toolkit.c.usertoken_refresh = partial(_refresh_and_save_token, user_name)
        else:
            log.warn('The user is not currently logged...')

    def _get_previous_page(self, default_page):
        if 'came_from' not in toolkit.request.params:
            came_from_url = toolkit.request.headers.get('Referer', default_page)
        else:
            came_from_url = toolkit.request.params.get('came_from', default_page)

        came_from_url_parsed = urlparse(came_from_url)

        # Avoid redirecting users to external hosts
        if came_from_url_parsed.netloc != '' and came_from_url_parsed.netloc != toolkit.request.host:
            came_from_url = default_page

        # When a user is being logged and REFERER == HOME or LOGOUT_PAGE
        # he/she must be redirected to the dashboard
        pages = ['/', '/user/logged_out_redirect']
        if came_from_url_parsed.path in pages:
            came_from_url = default_page

        return came_from_url

    def login(self):
        log.debug('login')

        oauth2helper = oauth2.OAuth2Helper()

        # Log in attemps are fired when the user is not logged in and they click
        # on the log in button

        # Get the page where the user was when the loggin attemp was fired
        # When the user is not logged in, he/she should be redirected to the dashboard when
        # the system cannot get the previous page
        came_from_url = self._get_previous_page(constants.INITIAL_PAGE)

        oauth2helper.challenge(came_from_url)

    def abort(self, status_code, detail, headers, comment):
        log.debug('abort')

        # If the user is authenticated, but they cannot access a protected resource, the system
        # should redirect them to the previous page. If the user is not redirected, the system
        # will try to reauthenticate the user generating a redirect loop:
        # (authenticate -> user not allowed -> auto log out -> authenticate -> ...)
        # If the user is not authenticated, the system should start the authentication process

        if toolkit.c.user:  # USER IS AUTHENTICATED
            # When the user is logged in, he/she should be redirected to the main page when
            # the system cannot get the previous page
            came_from_url = self._get_previous_page('/')

            # Init headers and set Location
            if headers is None:
                headers = {}
            headers['Location'] = came_from_url

            # 302 -> Found
            return 302, detail, headers, comment
        else:                # USER IS NOT AUTHENTICATED
            # By not modifying the received parameters, the authentication process will start
            return status_code, detail, headers, comment

    def get_auth_functions(self):
        # we need to prevent some actions being authorized.
        return {
            'user_create': user_create,
            'user_update': user_update,
            'user_reset': user_reset,
            'request_reset': request_reset
        }


