OAuth2 CKAN extension
=====================

[![Build Status](https://travis-ci.org/conwetlab/ckanext-oauth2.svg?branch=master)](https://travis-ci.org/conwetlab/ckanext-oauth2)
[![Coverage Status](https://coveralls.io/repos/github/conwetlab/ckanext-oauth2/badge.svg?branch=master)](https://coveralls.io/github/conwetlab/ckanext-oauth2?branch=master)

The OAuth2 extension allows site visitors to login through an OAuth2 server.

**Note**: This extension is being tested in CKAN 2.6, 2.7 and 2.8. These are therefore considered as the supported versions


## Links

1. [Activating & Installing the plugin](https://github.com/conwetlab/ckanext-oauth2/wiki/Activating-and-Installing)
2. [Starting CKAN over HTTPs](https://github.com/conwetlab/ckanext-oauth2/wiki/Starting-CKAN-over-HTTPs)
3. [How it works?](https://github.com/conwetlab/ckanext-oauth2/wiki/How-it-works%3F)



# Multiple SSO 
Add the SSO providers yaml file in  `ckan.oauth2.config_path` env.

Example of YAML file with list of SSO
``` yaml
providers:
  - name: github
    authorization_endpoint: https://github.com/login/oauth/authorize
    token_endpoint:  https://github.com/login/oauth/access_token
    profile_api_url: https://api.github.com/user/emails
    client_id: xxxxxxxxxxxxxxxxxxxxxxx
    client_secret: xxxxxxx-xxxxx-xxxxx-xxxxx
    scope: read:user,user:email
    profile_api_user_field: login
    profile_api_fullname_field : name
    profile_api_mail_field : email
  - name: microsoft
    authorization_endpoint: https://login.microsoftonline.com/aa097e38-5226-425f-944c-x32k3kj3/oauth2/v2.0/authorize
    token_endpoint:  https://login.microsoftonline.com/aa097e38-5226-425f-944c-x32k3kj3/oauth2/v2.0/token
    profile_api_url: https://graph.microsoft.com/v1.0/me
    client_id:  xxxxxxxxxxxxxxxxxxxxxxx
    client_secret: xxxxxxx-xxxxx-xxxxx-xxxxx
    scope: profile openid User.Read email
    profile_api_user_field: displayName
    profile_api_fullname_field : displayName
    profile_api_mail_field : userPrincipalName
```

## Credits

Based on the idea proposed by [Etalab](https://github.com/etalab/ckanext-oauth2)
