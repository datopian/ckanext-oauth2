CAME_FROM_FIELD = 'came_from'
INITIAL_PAGE = '/dashboard'

# Session keys for the OAuth2 flow. The state is a random, single-use nonce
# stored server-side and validated on callback (CSRF protection). came_from is
# stored here too so it never travels in the client-visible state param, which
# is what previously allowed an open redirect.
STATE_SESSION_KEY = 'ckanext-oauth2:state'
CAME_FROM_SESSION_KEY = 'ckanext-oauth2:came_from'
