# coding=utf-8
"""Manage Robinhood Sessions."""
import json
import logging
import logging.config
import subprocess
import uuid
from logging import Logger
from pathlib import Path
from typing import Any, Dict, Optional, TYPE_CHECKING, Tuple, Union, cast
from urllib.request import getproxies

import certifi
import pyotp
import requests
from httplib2 import Response
from marshmallow import Schema, fields, post_load
from requests.exceptions import HTTPError
from requests.structures import CaseInsensitiveDict
import pendulum
from yarl import URL

from pyrh import urls
from pyrh.constants import CLIENT_ID, EXPIRATION_TIME, TIMEOUT
from pyrh.exceptions import AuthenticationError, PyrhValueError
from pyrh.models.base import BaseModel, BaseSchema, JSON
from pyrh.models.oauth import (CHALLENGE_TYPE_VAL, OAuth, OAuthSchema)
from pyrh.util import robinhood_headers, JSON_ENCODING

parent_dir = Path(__file__).parent
# log_conf_path = os.path.join(parent_dir, os.pardir, os.pardir, os.pardir, "conf", "logging.conf")
# logging.config.fileConfig(log_conf_path)

# TODO: merge get and post duplicated code into a single function.

# Types
if TYPE_CHECKING:  # pragma: no cover
    CaseInsensitiveDictType = CaseInsensitiveDict[str]
else:
    CaseInsensitiveDictType = CaseInsensitiveDict
Proxies = Dict[str, str]

HEADERS: CaseInsensitiveDictType = CaseInsensitiveDict(
    robinhood_headers
)
"""Headers used when performing requests with robinhood api."""


class SessionManager(BaseModel):
    """Manage connectivity with Robinhood API.

    This class manages logging in and multifactor authentication. Optionally,
    it can automatically authenticate for automation systems

    Example:
        >>> sm = SessionManager(username="USERNAME", password="PASSWORD")
        >>> sm.login()  # xdoctest: +SKIP
        >>> sm.logout()  # xdoctest: +SKIP

    Example:
        >>> sm = SessionManager(username="USERNAME", password="PASSWORD", mfa="16 DIGIT QR CODE")

    If you want to bypass manual MFA authentication, you can supply your 16-digit QR code from Robinhood as a parameter
    as shown.

    Args:
        username: The username to use for logging in to Robinhood
        password: The password to use for logging in to Robinhood
        mfa: The 16 character QR code used to authenticate MFA automatically
        challenge_type: Either sms or email (only if not using mfa)
        headers: Any optional header dict modifications for the session
        proxies: Any optional proxy dict modification for the session
        **kwargs: Any other passed parameters as converted to instance attributes

    Attributes:
        session: A requests session instance
        expires_at: The time the oauth token will expire at, default is 1970-01-01 00:00:00
        device_token: A random guid representing the current device

    """

    def __init__(
            self,
            username: Optional[str] = None,
            password: Optional[str] = None,
            mfa: Optional[str] = "",
            challenge_type: Optional[str] = "sms",
            headers: Optional[CaseInsensitiveDictType] = None,
            proxies: Optional[Proxies] = None,
            **kwargs: Any
    ) -> None:
        self.__logger: Logger = logging.getLogger(__name__)
        self.__logger.info("Initializing session manager!")
        self.mfa = mfa
        self.__logger.info("MFA Done!")
        self.session: requests.Session = requests.session()
        self.__logger.info("Session done!")
        self.session.headers = HEADERS if headers is None else headers
        self.__logger.info("Headers done!")
        self.session.proxies = getproxies() if proxies is None else proxies
        self.__logger.info("Proxies done!")
        self.session.verify = certifi.where()
        self.__logger.info("certifi done!")
        self.expires_at = pendulum.datetime(1970, 1, 1, tz='UTC')  # some time in the past
        self.__logger.info("expires_at done!")
        self.username: str = username
        self.__logger.info("username done!")
        self.password: str = password
        self.__logger.info("password done!")
        if challenge_type not in ["email", "sms"]:
            raise ValueError("challenge_type must be email or sms")
        self.challenge_type: str = challenge_type
        self.__logger.info("challenge_type done!")
        self.device_token: str = kwargs.pop("device_token", str(uuid.uuid4()))
        self.__logger.info("device_token done!")
        self.oauth: OAuth = kwargs.pop("oauth", OAuth())
        self.__logger.info("oauth done!")

        super().__init__(**kwargs)
        self.__logger.info("super() done!")

    def __repr__(self) -> str:
        """Return the object as a string.

        Returns:
            The string representation of the object.

        """
        return f"SessionManager<{self.username}>"

    def _challenge_oauth2(self, oauth: OAuth, oauth_payload: JSON) -> OAuth:
        """Process the ouath challenge flow.

        Args:
            oauth: An oauth response model from a login request.
            oauth_payload: The payload to use once the challenge has been processed.

        Returns:
            An OAuth response model from the login request.

        Raises:
            AuthenticationError: If there is an error in the initial challenge response.

        # noqa: DAR202
        https://github.com/terrencepreilly/darglint/issues/81

        """
        # login challenge
        challenge_url = urls.challenge(oauth.challenge.id)
        print(
            f"Input challenge code from {oauth.challenge.type.capitalize()} "
            f"({oauth.challenge.remaining_attempts}/"
            f"{oauth.challenge.remaining_retries}):"
        )
        challenge_code = input()
        challenge_payload = {"response": str(challenge_code)}
        challenge_header = CaseInsensitiveDict(
            {"X-ROBINHOOD-CHALLENGE-RESPONSE-ID": str(oauth.challenge.id)}
        )
        oauth_inner, res = self.post(
            challenge_url,
            data=challenge_payload,
            raise_errors=False,
            headers=challenge_header,
            auto_login=False,
            return_response=True,
            schema=OAuthSchema(),
        )
        if res.status_code == requests.codes.ok:
            try:
                # the cast is required for mypy
                return cast(
                    OAuth,
                    self.post(
                        urls.OAUTH,
                        data=oauth_payload,
                        headers=challenge_header,
                        auto_login=False,
                        schema=OAuthSchema(),
                    ),
                )
            except HTTPError:
                raise AuthenticationError("Error in finalizing auth token")
        elif oauth_inner.is_challenge and oauth_inner.challenge.can_retry:
            print("Invalid code entered")
            return self._challenge_oauth2(oauth, oauth_payload)
        else:
            raise AuthenticationError("Exceeded available attempts or code expired")

    def _challenge_response(self, challenge_id, mfa_code):
        request_url = urls.CHALLENGE / f"{challenge_id}/respond/"
        payload = {"response": mfa_code}
        data, res = self.post(
            request_url,
            data=payload,
            raise_errors=False,
            auto_login=False,
            return_response=True
        )
        if res.status_code != requests.codes.ok:
            self.logger.error("Challenge Response Error")
        elif res.status_code == requests.codes.ok and data["status"] == "validated":
            return True
        else:
            raise AuthenticationError("Challenge Response Error")
        return False

    def _configure_manager(self, oauth: OAuth) -> None:
        """Process an authentication response dictionary.

        This method updates the internal state of the session based on a login or
        token refresh request.

        Args:
            oauth: An oauth response model from a login request.

        """
        self.oauth = oauth
        self.expires_at: pendulum.datetime = pendulum.now(tz="UTC").add(seconds=self.oauth.expires_in)
        self.session.headers.update(
            {"Authorization": f"Bearer {self.oauth.access_token}"}
        )

    @staticmethod
    def _generate_request_id():
        return str(uuid.uuid4())

    def get(self,
            url: Union[str, URL],
            params: Optional[Dict[str, Any]] = None,
            headers: Optional[CaseInsensitiveDictType] = None,
            raise_errors: bool = True,
            return_response: bool = False,
            auto_login: bool = True,
            schema: Optional[Schema] = None,
            many: bool = False,
            ) -> Tuple[Dict[str, Any], Response] | Dict[str, Any]:
        """Run a wrapped session HTTP GET request.

        Note:
            This method automatically prompts the user to log in if not already logged
            in.

        Args:
            url: The url to get from.
            params: query string parameters
            headers: A dict adding to and overriding the session headers.
            raise_errors: Whether to raise errors on GET request result.
            return_response: Whether to return a `requests.Response` object or the
                JSON response from the request.
            auto_login: Whether to automatically login on restricted endpoint
                errors.
            schema: An instance of a `marshmallow.Schema` that represents the object
                to build.
            many: Whether to treat the output as a list of the passed schema.

        Returns:
            A JSON dictionary or a constructed object if a schema is passed. If \
                `return_response` is set then a tuple of (response, data) is passed.

        Raises:
            PyrhValueError: If the schema is not an instance of `Schema` and is instead
                a class.

        """
        # Guard against common gotcha, passing schema class instead of instance.
        if isinstance(schema, type):
            raise PyrhValueError("Passed Schema should be an instance not a class.")
        params = {} if params is None else params
        res = self.session.get(
            str(url),
            params=params,
            timeout=TIMEOUT,
            headers=self.session.headers if headers is None else headers,
        )
        if res.status_code == 401 and auto_login:
            self.login(force_refresh=True)
            res = self.session.get(
                str(url),
                params=params,
                timeout=TIMEOUT,
                headers=self.session.headers if headers is None else headers,
            )
        if raise_errors:
            res.raise_for_status()

        data = res.json() if schema is None else schema.load(res.json(), many=many)

        return (data, res) if return_response else data

    def _get_mfa_code(self):
        get_otp_proc = subprocess.run(["/opt/homebrew/bin/apw", "otp", "get", "robinhood.com"],
                                      capture_output=True,
                                      text=True)
        output, error = get_otp_proc.stdout, get_otp_proc.stderr
        self.logger.info(f"get_otp_proc output: {output}")
        self.logger.info(f"get_otp_proc error: {error}")
        result_json = json.loads(output)
        self.logger.info(result_json)
        return result_json["results"][0]["code"]

    def _get_oauth_payload(self):
        oauth_payload = {
            "client_id":                        CLIENT_ID,
            "create_read_only_secondary_token": True,
            "device_token":                     self.device_token,
            "expires_in":                       EXPIRATION_TIME,
            "grant_type":                       "password",
            "password":                         self.password,
            "request_id":                       self._generate_request_id(),
            "scope":                            "internal",
            "token_request_path":               "/login",
            "username":                         self.username
        }
        self.logger.info(oauth_payload)
        return oauth_payload

    def _login_oauth2(self) -> None:
        """Create a new oauth2 token.

        Raises:
            AuthenticationError: If the login credentials are not set, if a challenge
                wasn't accepted, or if a mfa code is not accepted.

        """
        self.logger.info("_login_oauth2!")
        self.session.headers.pop("Authorization", None)
        self.logger.info("_login_oauth2 Authorization popped!")
        oauth_payload = self._get_oauth_payload()
        self.logger.info(f"_login_oauth2 oauth_payload generated: {oauth_payload}")
        workflow_id = self._mfa_oauth2(oauth_payload)
        self.logger.info(f"_login_oauth2 workflow_id generated: {workflow_id}")
        oauth = self._mfa_login_workflow(workflow_id, oauth_payload)

        if not oauth.is_valid:
            if hasattr(oauth, "error"):
                msg = f"{oauth.error}"
            elif hasattr(oauth, "detail"):
                msg = f"{oauth.detail}"
            else:
                msg = "Unknown login error"
            raise AuthenticationError(msg)
        else:
            self._configure_manager(oauth)

    def _mfa_login_workflow(self, workflow_id, oauth_payload) -> OAuth | None:
        machine_id = self._user_machine_request(workflow_id)
        challenge_id = self._user_view_get(machine_id)

        if self.mfa != "":
            mfa_code = pyotp.TOTP(self.mfa).now()
        else:
            mfa_code = self._get_mfa_code()

        if self._challenge_response(challenge_id, mfa_code) and self._user_view_post(machine_id):
            return self._mfa_oauth2(oauth_payload, OAuthSchema())

    def _mfa_oauth2(self, oauth_payload: JSON, schema: OAuthSchema = None, attempts: int = 3) -> str | OAuth:
        """Mfa auth flow.

         For people with 2fa.

        Args:
            oauth_payload: JSON payload to send on mfa approval.
            attempts: The number of attempts to allow for mfa approval.

        Returns:
            An OAuth response model object.

        Raises:
            AuthenticationError: If the mfa code is incorrect more than specified \
                number of attempts.

        """
        self.logger.info("_mfa_oauth2!")
        oauth, res = self.post(
            urls.OAUTH,
            data=oauth_payload,
            raise_errors=False,
            auto_login=False,
            return_response=True,
            schema=schema,
        )
        self.logger.info("_mfa_oauth2 posted request!")
        attempts -= 1
        self.logger.info(f"_mfa_oauth2 status_code: {res.status_code}")
        if isinstance(oauth, dict):
            self.logger.info(f"_mfa_oauth2 oauth keys: {oauth.keys()}")
        else:
            self.logger.info(f"_mfa_oauth2 oauth dict: {oauth.__dict__}")
        self.logger.info(f"_mfa_oauth2 oauth_payload json: {json.dumps(oauth_payload)}")
        if res.status_code == 403:
            workflow_id = oauth["verification_workflow"]["id"]
            return workflow_id

        if res.status_code != requests.codes.ok and attempts > 0:
            self.logger.error("Invalid mfa code")
            return self._mfa_oauth2(oauth_payload, schema, attempts)
        elif res.status_code == requests.codes.ok:
            # TODO: Write mypy issue on why this needs to be casted?
            return cast(OAuth, oauth)
        else:
            raise AuthenticationError("Too many incorrect mfa attempts")

    def post(
            self,
            url: Union[str, URL],
            data: Optional[JSON] = None,
            headers: Optional[CaseInsensitiveDictType] = None,
            raise_errors: bool = True,
            return_response: bool = False,
            auto_login: bool = True,
            schema: Optional[Schema] = None,
            many: bool = False,
    ) -> Any:
        """Run a wrapped session HTTP POST request.

        Note:
            This method automatically prompts the user to log in if not already logged
            in.

        Args:
            url: The url to post to.
            data: The payload to POST to the endpoint.
            headers: A dict adding to and overriding the session headers.
            return_response: Whether to return a `requests.Response` object or the
                JSON response from the request.
            raise_errors: Whether to raise errors on POST request.
            auto_login: Whether to automatically login on restricted endpoint
                errors.
            schema: An instance of a `marshmallow.Schema` that represents the object
                to build.
            many: Whether to treat the output as a list of the passed schema.

        Returns:
            A JSON dictionary or a constructed object if a schema is passed. If \
                `return_response` is set then a tuple of (response, data) is passed.

        Raises:
            PyrhValueError: If the schema is not an instance of `Schema` and is instead
                a class.

        """
        # Guard against common gotcha, passing schema class instead of instance.
        self.logger.info("_post!")
        if isinstance(schema, type):
            raise PyrhValueError("Passed Schema should be an instance not a class.")
        self.logger.info("_post posting request!")
        res = self.session.post(
            str(url),
            json=data,
            timeout=TIMEOUT,
            headers=self.session.headers if headers is None else headers,
        )
        self.logger.info("_post got response!")
        self.logger.info(f"{str(url)}, {json.dumps(data)}, {self.session.headers}")
        if (res.status_code == 401) and auto_login:
            self.login(force_refresh=True)
            res = self.session.post(
                str(url),
                json=data,
                timeout=TIMEOUT,
                headers=self.session.headers if headers is None else headers,
            )
        if raise_errors:
            res.raise_for_status()

        data = res.json() if schema is None else schema.load(res.json(), many=many)

        return (data, res) if return_response else data

    def _refresh_oauth2(self) -> None:
        """Refresh an oauth2 token.

        Raises:
            AuthenticationError: If refresh_token is missing or if there is an error
                when trying to refresh a token.

        """
        if not self.oauth.is_valid:
            raise AuthenticationError("Cannot refresh login with unset refresh token")
        re_login_payload = {
            "grant_type":    "refresh_token",
            "refresh_token": self.oauth.refresh_token,
            "scope":         "internal",
            "client_id":     CLIENT_ID,
            "expires_in":    EXPIRATION_TIME,
        }
        self.session.headers.pop("Authorization", None)
        try:
            oauth = self.post(
                urls.OAUTH,
                data=re_login_payload,
                auto_login=False,
                schema=OAuthSchema(),
            )
        except HTTPError:
            raise AuthenticationError("Failed to refresh token")

        self._configure_manager(oauth)

    def _user_machine_request(self, user_workflow_id):
        payload = \
            {
                "device_id": self.device_token,
                "flow":      "suv",
                "input":
                             {
                                 "workflow_id": user_workflow_id
                             }
            }
        self.session.headers["Content-Type"] = JSON_ENCODING
        data, res = self.post(
            urls.USER_MACHINE,
            data=payload,
            raise_errors=False,
            auto_login=False,
            return_response=True
        )
        if res.status_code == requests.codes.ok:
            return data["id"]
        else:
            self.logger.info(res.status_code)
            raise AuthenticationError("User Machine Error")

    def _user_view_get(self, machine_id):
        request_url = urls.INQUIRIES / f"{machine_id}/user_view/"
        data, res = self.get(
            request_url,
            raise_errors=False,
            auto_login=False,
            return_response=True
        )
        if res.status_code != requests.codes.ok:
            self.logger.error("User View Error")
        elif res.status_code == requests.codes.ok:
            return data["context"]["sheriff_challenge"]["id"]
        else:
            raise AuthenticationError("User View Error")

    def _user_view_post(self, machine_id):
        request_url = urls.INQUIRIES / f"{machine_id}/user_view/"
        payload = {"sequence": 0, "user_input": {"status": "continue"}}
        data, res = self.post(
            request_url,
            data=payload,
            raise_errors=False,
            auto_login=False,
            return_response=True
        )
        if res.status_code != requests.codes.ok:
            self.logger.error("User View Error")
        elif res.status_code == requests.codes.ok and data["type_context"]["result"] == "workflow_status_approved":
            return True
        else:
            raise AuthenticationError("User View Error")
        return False

    @property
    def authenticated(self) -> bool:
        """Check if the session is authenticated.

        Returns:
            Whether the current session is authenticated.
        """
        return "Authorization" in self.session.headers and not self.token_expired

    @property
    def logger(self):
        return self.__logger

    def login(self, force_refresh: bool = False) -> None:
        """Login to the session.

        This method logs the user in if they are not already and otherwise refreshes
        the oauth token if it is expired.

        Args:
            force_refresh: If already logged in, whether to force an oauth token
                refresh.

        """
        if "Authorization" not in self.session.headers:
            # If login credentials are provided
            if self.login_set:
                self._login_oauth2()
            # Relogin using existing valid token
            elif self.oauth and self.oauth.is_valid:
                self._configure_manager(self.oauth)
            else:
                raise AuthenticationError("Valid auth token not sent and login credentials missing")

        elif self.oauth.is_valid and (self.oauth.token_expired or force_refresh):
            self._refresh_oauth2()

    @property
    def login_set(self) -> bool:
        """Check if login info is properly configured.

        Returns:
            Whether username and password are set.
        """
        return self.password is not None and self.username is not None

    def logout(self) -> None:
        """Logout from the session.

        Raises:
            AuthenticationError: If there is an error when logging out.

        """
        logout_payload = {"client_id": CLIENT_ID, "token": self.oauth.refresh_token}
        try:
            self.post(urls.OAUTH_REVOKE, data=logout_payload, auto_login=False)
            self.oauth = OAuth()
            self.session.headers.pop("Authorization", None)
        except HTTPError:
            raise AuthenticationError("Could not log out")

    @property
    def token_expired(self) -> bool:
        """Check if the issued auth token has expired.

        Returns:
            True if expired otherwise False
        """
        return pendulum.now(tz="UTC") > self.expires_at


class SessionManagerSchema(BaseSchema):
    """Schema class for the SessionManager model."""

    __model__ = SessionManager

    # Call untyped "Email" in typed context
    username = fields.Email()  # type: ignore
    password = fields.Str()
    challenge_type = fields.Str(validate=CHALLENGE_TYPE_VAL)
    oauth = fields.Nested(OAuthSchema)
    expires_at = fields.AwareDateTime()
    device_token = fields.Str()
    headers = fields.Dict()
    proxies = fields.Dict()

    @post_load
    def make_object(self, data: JSON, **kwargs: Any) -> SessionManager:
        """Override default method to configure SessionManager object on load.

        Args:
            data: The JSON dictionary to process
            **kwargs: Not used but matches signature of `BaseSchema.make_object`

        Returns:
            A configured instance of SessionManager.
        """
        oauth: OAuth | None = data.pop("oauth", None)
        expires_at = data.pop("expires_at", None)
        session_manager = self.__model__(**data)

        if oauth is not None and oauth.is_valid:
            session_manager.oauth = oauth
            session_manager.session.headers.update(
                {"Authorization": f"Bearer {session_manager.oauth.access_token}"}
            )
        if expires_at:
            session_manager.expires_at = expires_at

        return session_manager
