# Constants
CLIENT_ID: str = "c82SH0WZOsabOXGP2sxqcj34FxkvfnWRZBKlBjFS"
""" Robinhood client id."""
EXPIRATION_TIME: int = 734000
""" Default expiration time for requests.
    8.5 days (you have a small window to refresh after this)
    I would refresh the token proactively every day in a script
"""

TIMEOUT: int = 15
""" Default timeout in seconds. """
