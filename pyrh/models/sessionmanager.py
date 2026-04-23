# coding=utf-8
"""Manage Robinhood Sessions."""
import json
import logging
import logging.config
import os
import shutil
import subprocess
import uuid
from logging import Logger
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, TYPE_CHECKING, Tuple, Union, cast
from urllib.request import getproxies

import certifi
import pendulum
import pyotp
import requests
from httplib2 import Response
from marshmallow import Schema, fields, post_load
from pyrh import urls
from pyrh.constants import CLIENT_ID, EXPIRATION_TIME, TIMEOUT
from pyrh.exceptions import AuthenticationError, PyrhValueError
from pyrh.models.base import BaseModel, BaseSchema, JSON
from pyrh.models.oauth import CHALLENGE_TYPE_VAL, OAuth, OAuthSchema
from pyrh.util import JSON_ENCODING, robinhood_headers
from requests.exceptions import HTTPError
from requests.structures import CaseInsensitiveDict
from yarl import URL

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

# ``HEADERS`` is exposed as a read-only ``MappingProxyType`` so that
# accidental direct mutation (``HEADERS["X"] = "y"``) raises ``TypeError``
# instead of silently leaking into every future ``SessionManager`` instance.
# The per-instance copy still happens in ``SessionManager.__init__`` via
# ``CaseInsensitiveDict(HEADERS)``; ``CaseInsensitiveDict`` accepts any
# mapping at construction time, so the read-only view is a drop-in substitute
# for the previous mutable ``CaseInsensitiveDict`` at the module level.
HEADERS: Mapping[str, str] = MappingProxyType(dict(robinhood_headers))
"""Read-only default headers used when performing requests with the Robinhood API."""


def _truncate_body(res: Any, limit: int = 200) -> str:
    """Return a safely-truncated representation of a response body for logging.

    Extracts ``res.text`` if it is a string and truncates it to ``limit``
    characters. Returns ``""`` for Mock objects, missing attrs, or anything
    non-string — this keeps error messages clean and predictable across real
    ``requests.Response`` objects and test doubles.

    For binary Content-Types (e.g. image/png, application/octet-stream) the
    body is NOT emitted — we return a ``<N bytes binary>`` size marker
    instead. This avoids dumping raw bytes into log messages and error
    strings, which tends to corrupt terminals and bloats error messages.
    """
    text = getattr(res, "text", "")
    if not isinstance(text, str):
        return ""
    headers = getattr(res, "headers", {}) or {}
    content_type = ""
    try:
        content_type = headers.get("Content-Type", "") or ""
    except AttributeError:
        content_type = ""
    if content_type and not content_type.startswith(("text/", "application/json")):
        content = getattr(res, "content", b"") or b""
        try:
            size = len(content)
        except TypeError:
            size = 0
        return f"<{size} bytes binary>"
    return text[:limit]


def _is_permanent_refresh_failure(err: Exception) -> bool:
    """Return True when a refresh-token failure is permanent.

    Permanent failures (401 unauthorized, 403 forbidden, any 4xx from the
    oauth endpoint) mean the refresh token was revoked or is otherwise
    invalid — silently falling back to a password-grant login would mask the
    root cause and show the user an unrelated MFA prompt.

    Transient failures (5xx, network) are recoverable and the caller may
    choose to fall back to an interactive login.

    The classification uses the ``status_code`` attribute set on the
    AuthenticationError by ``_refresh_oauth2`` — if absent (e.g. an
    unrelated AuthenticationError such as "No refresh token available"),
    the failure is treated as permanent by default so it is not silently
    swallowed.
    """
    status = getattr(err, "status_code", None)
    if status is None:
        return True
    # 408 Request Timeout, 425 Too Early, 429 Too Many Requests are 4xx in
    # range but semantically transient — the refresh token itself is fine, the
    # server just wants us to back off. Treat as transient so the caller can
    # fall back to a fresh login (or retry) rather than dying on a throttling
    # spike.
    _TRANSIENT_4XX = {408, 425, 429}
    if int(status) in _TRANSIENT_4XX:
        return False
    # 4xx → permanent; 5xx → transient; anything else → treat as permanent.
    return 400 <= int(status) < 500


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
        **kwargs: Any,
    ) -> None:
        self.__logger: Logger = logging.getLogger(__name__)
        self.__logger.info("Initializing session manager!")
        self.mfa = mfa
        self.__logger.info("MFA Done!")
        self.session: requests.Session = requests.session()
        self.__logger.info("Session done!")
        # Always copy so the module-level HEADERS dict (and any caller-supplied
        # dict) is never mutated by per-session header changes like
        # Authorization. See coverage pass 2026-04-17 — this surfaced as
        # cross-test leakage of `Authorization: Bearer ...` between
        # SessionManager instances.
        self.session.headers = CaseInsensitiveDict(
            HEADERS if headers is None else headers
        )
        self.__logger.info("Headers done!")
        self.session.proxies = getproxies() if proxies is None else proxies
        self.__logger.info("Proxies done!")
        self.session.verify = certifi.where()
        self.__logger.info("certifi done!")

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

        epoch_time = pendulum.datetime(1970, 1, 1, tz="UTC")

        self.expires_at: pendulum.datetime = (
            pendulum.now("UTC").add(seconds=self.oauth.expires_in)
            if hasattr(self.oauth, "access_token") and self.oauth.expires_in
            else epoch_time
        )

        self.__logger.info("expires_at done!")
        self.__logger.info(f"type(self.expires_at): {type(self.expires_at)}")

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
            except HTTPError as e:
                err_res = getattr(e, "response", None)
                status = getattr(err_res, "status_code", "?")
                raise AuthenticationError(
                    f"Error in finalizing auth token: status={status} "
                    f"body={_truncate_body(err_res)}"
                ) from e
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
            return_response=True,
        )
        if res.status_code != requests.codes.ok:
            # Previously this branch just logged and returned False, which the
            # caller interpreted as "MFA rejected" even when the real cause was
            # a 5xx / 429 / network error. Surface the real status so the user
            # sees "Challenge response HTTP 503: …" instead of a misleading
            # "wrong MFA code" retry prompt.
            raise AuthenticationError(
                f"Challenge response HTTP status={res.status_code} "
                f"body={_truncate_body(res)}"
            ) from None
        if data["status"] == "validated":
            return True
        # 200 received but not validated — genuine "wrong code" signal.
        return False

    def _configure_manager(self, oauth: OAuth) -> None:
        """Process an authentication response dictionary.

        This method updates the internal state of the session based on a login or
        token refresh request.

        Args:
            oauth: An oauth response model from a login request.

        """
        self.oauth = oauth
        self.expires_at: pendulum.datetime = pendulum.now(tz="UTC").add(
            seconds=self.oauth.expires_in
        )
        self.session.headers.update(
            {"Authorization": f"Bearer {self.oauth.access_token}"}
        )

    @staticmethod
    def _generate_request_id():
        return str(uuid.uuid4())

    def _log_bearer_fingerprint(self, label: str, authorization: Optional[str]) -> None:
        """Emit a short, non-reversible fingerprint of the Authorization
        header at DEBUG so operators can diff pre- vs post-refresh bearers
        without the raw token ever hitting logs.
        """
        if not authorization:
            self.logger.debug("bearer_fingerprint %s=<absent>", label)
            return
        import hashlib

        digest = hashlib.sha256(authorization.encode("utf-8")).hexdigest()[:8]
        self.logger.debug("bearer_fingerprint %s=%s", label, digest)

    def get(
        self,
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
            old_authorization = self.session.headers.get("Authorization")
            self._log_bearer_fingerprint("pre-refresh", old_authorization)
            self.login(force_refresh=True)
            new_authorization = self.session.headers.get("Authorization")
            self._log_bearer_fingerprint("post-refresh", new_authorization)
            if new_authorization == old_authorization:
                # Refresh claimed success but the Authorization header is
                # unchanged — retrying would replay the same stale bearer and
                # produce another 401. Surface the inconsistency instead of
                # silently looping.
                raise AuthenticationError(
                    "Refresh succeeded but Authorization header was not updated"
                )
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
        """Resolve the MFA/OTP code.

        Resolution order for the OTP helper binary:

        1. ``PYRH_OTP_COMMAND`` environment variable — absolute path to an
           executable whose stdout is JSON of the shape
           ``{"results": [{"code": "<6-digit-otp>"}]}``. Use this on hosts
           where the helper lives outside ``PATH`` (CI images, service
           accounts, Airflow workers).
        2. ``shutil.which("apw")`` — portable discovery of the Apple
           Password Manager (``apw``) helper wherever it lives on the
           operator's ``PATH`` (Apple Silicon, Intel macOS, or Linux
           containers with a PATH-installed ``apw``).
        3. Interactive ``input()`` prompt — last-resort fallback when no
           helper binary was found.

        The two failure modes of the helper are intentionally split:

        - helper unavailable / timed out (``FileNotFoundError``,
          ``subprocess.TimeoutExpired``): treat as "not installed here"
          and fall back to ``input()``.
        - helper ran but emitted malformed JSON / missing keys: raise
          ``AuthenticationError`` so the operator investigates the
          broken contract rather than silently retyping an OTP.

        Rationale: the previous implementation hardcoded
        ``/opt/homebrew/bin/apw``. That path only exists on Apple Silicon
        macOS with Homebrew — it breaks CI, Linux, and headless Airflow
        deployments.
        """
        otp_cmd = os.environ.get("PYRH_OTP_COMMAND") or shutil.which("apw")
        if otp_cmd:
            try:
                get_otp_proc = subprocess.run(
                    [otp_cmd, "otp", "get", "robinhood.com"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if get_otp_proc.returncode == 0:
                    try:
                        result_json = json.loads(get_otp_proc.stdout)
                        return result_json["results"][0]["code"]
                    except (json.JSONDecodeError, KeyError, IndexError) as e:
                        self.logger.error("OTP helper returned malformed payload: %s", e)
                        raise AuthenticationError(
                            "APW payload is malformed; refusing to fall back to "
                            "interactive input"
                        ) from e
            except (FileNotFoundError, subprocess.TimeoutExpired) as e:
                self.logger.warning(
                    "OTP helper %s unavailable, falling back to input(): %s",
                    otp_cmd,
                    e,
                )

        # Fall back to manual input
        self.logger.info("Requesting manual MFA code entry")
        return input("Enter Robinhood MFA code: ").strip()

    def _get_oauth_payload(self):
        oauth_payload = {
            "client_id": CLIENT_ID,
            "create_read_only_secondary_token": True,
            "device_token": self.device_token,
            "expires_in": EXPIRATION_TIME,
            "grant_type": "password",
            "password": self.password,
            "request_id": self._generate_request_id(),
            "scope": "internal",
            "token_request_path": "/login",
            "username": self.username,
        }
        self.logger.debug(
            "OAuth payload generated for user=%s", self.username[:3] + "***"
        )
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
        self.logger.debug("_login_oauth2 oauth_payload generated (redacted)")
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

    def _mfa_login_workflow(self, workflow_id, oauth_payload) -> OAuth:
        machine_id = self._user_machine_request(workflow_id)
        challenge_id, challenge_type = self._user_view_get(machine_id)
        self.logger.info(
            f"_mfa_login_workflow| challenge_type: {challenge_type}, challenge_id: {challenge_id}"
        )

        if challenge_type == "prompt":
            self.logger.info(
                "Device approval required — waiting for user to approve on mobile app"
            )
            self._poll_prompt_approval(challenge_id)
        else:
            # SMS / TOTP fallback
            if self.mfa != "":
                mfa_code = pyotp.TOTP(self.mfa).now()
            else:
                mfa_code = self._get_mfa_code()

            if not self._challenge_response(challenge_id, mfa_code):
                raise AuthenticationError("Challenge response was not validated")

        if not self._user_view_post(machine_id):
            raise AuthenticationError(
                "User View POST was not approved; MFA login workflow aborted."
            )
        return self._mfa_oauth2(oauth_payload, OAuthSchema())

    def _mfa_oauth2(
        self, oauth_payload: JSON, schema: OAuthSchema = None, attempts: int = 3
    ) -> str | OAuth:
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
        # Redact OAuth payload values: never log __dict__ or keys() values at INFO,
        # as the 200-branch `oauth` is an OAuth model carrying access_token /
        # refresh_token as attributes, identical leak class to bd227b3.
        self.logger.debug(
            "_mfa_oauth2 result type=%s keys=%s",
            type(oauth).__name__,
            sorted(vars(oauth) if hasattr(oauth, "__dict__") else oauth),
        )
        self.logger.debug("_mfa_oauth2 status=%s", res.status_code)
        if res.status_code == 403:
            # A 403 should carry a verification_workflow.id under the body,
            # but a malformed proxy / edge response can drop the shape. Wrap
            # so the operator sees "Malformed 403 body: …" instead of a raw
            # KeyError that masks the real authentication stage.
            try:
                workflow_id = oauth["verification_workflow"]["id"]
            except (KeyError, TypeError) as e:
                raise AuthenticationError(
                    f"Malformed 403 body: {_truncate_body(res)}"
                ) from e
            return workflow_id

        # Transport / upstream failures must NOT be retried with "Invalid mfa
        # code" — the user's MFA code is fine, the server is sick. Surface
        # the real status so the operator doesn't chase a phantom wrong-code
        # loop.
        _TRANSPORT_STATUSES = {429, 500, 502, 503, 504}
        if res.status_code in _TRANSPORT_STATUSES:
            raise AuthenticationError(
                f"OAuth transport error: status={res.status_code} "
                f"body={_truncate_body(res)}"
            ) from None

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
        self.logger.debug("POST %s status=%s", str(url), res.status_code)
        if (res.status_code == 401) and auto_login:
            old_authorization = self.session.headers.get("Authorization")
            self._log_bearer_fingerprint("pre-refresh", old_authorization)
            self.login(force_refresh=True)
            new_authorization = self.session.headers.get("Authorization")
            self._log_bearer_fingerprint("post-refresh", new_authorization)
            if new_authorization == old_authorization:
                # See matching note in `get()`: refresh claims success but
                # bearer is unchanged → retrying loops forever on the stale
                # token.
                raise AuthenticationError(
                    "Refresh succeeded but Authorization header was not updated"
                )
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
        """Refresh the OAuth token using the stored refresh_token.

        Raises:
            AuthenticationError: If refresh_token is missing or if there is an error
                when trying to refresh a token.

        """
        self.logger.info("Refreshing token")
        if (
            not self.oauth
            or not self.oauth.is_valid
            or not hasattr(self.oauth, "refresh_token")
        ):
            raise AuthenticationError("No refresh token available")

        refresh_payload = {
            "client_id": CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": self.oauth.refresh_token,
            "device_token": self.device_token,
            "scope": "internal",
        }

        try:
            oauth, res = self.post(
                urls.OAUTH,
                data=refresh_payload,
                raise_errors=False,
                auto_login=False,
                return_response=True,
                schema=OAuthSchema(),
            )
        except requests.RequestException as e:
            # A raw `requests` network-layer failure (DNS, TCP reset, read
            # timeout) has no HTTP status. Without a synthetic status_code
            # the `_is_permanent_refresh_failure` classifier would see
            # `status is None` and return True — killing the session on a
            # flaky WiFi blip. Attach 503 to force a transient classification
            # so the caller falls back to a fresh interactive login.
            err = AuthenticationError(f"refresh network error: {e}")
            err.status_code = 503
            raise err from e

        if (
            res.status_code == requests.codes.ok
            and hasattr(oauth, "is_valid")
            and oauth.is_valid
        ):
            self._configure_manager(oauth)
            self.logger.info("Token refreshed successfully")
        else:
            self.logger.warning("Token refresh failed, falling back to full login")
            err = AuthenticationError(
                f"Failed to refresh token: status={res.status_code} "
                f"body={_truncate_body(res)}"
            )
            # Attach the HTTP status so callers (notably `login`) can classify
            # the failure as permanent (401/403/4xx token revoked) vs
            # transient (5xx / network) without re-parsing the message.
            err.status_code = res.status_code
            raise err

    def _user_machine_request(self, user_workflow_id):
        payload = {
            "device_id": self.device_token,
            "flow": "suv",
            "input": {"workflow_id": user_workflow_id},
        }
        self.session.headers["Content-Type"] = JSON_ENCODING
        data, res = self.post(
            urls.USER_MACHINE,
            data=payload,
            raise_errors=False,
            auto_login=False,
            return_response=True,
        )
        if res.status_code == requests.codes.ok:
            return data["id"]
        else:
            self.logger.info(res.status_code)
            raise AuthenticationError(
                f"User Machine Error: status={res.status_code} "
                f"body={_truncate_body(res)}"
            )

    def _poll_prompt_approval(self, challenge_id, timeout=120, interval=5):
        """Poll /push/{challenge_id}/get_prompts_status/ for device approval.

        Args:
            challenge_id: The challenge UUID returned by the user_view endpoint.
            timeout: Maximum seconds to wait before raising AuthenticationError.
            interval: Seconds between each poll attempt.

        Returns:
            True when the challenge_status is ``"validated"``.

        Raises:
            AuthenticationError: If the challenge is denied, expired, times out,
                or if the poll endpoint raises ``requests.RequestException`` on
                three consecutive attempts.

        Notes:
            Only network-layer failures (``requests.RequestException``) are
            retried. Shape errors (``KeyError``, ``json.JSONDecodeError``, etc.)
            propagate unchanged so the operator sees the real cause instead of
            a misleading timeout.
        """
        import time

        prompt_url = str(
            urls.PUSH_PROMPT_STATUS / f"{challenge_id}/get_prompts_status/"
        )
        elapsed = 0
        consecutive_failures = 0
        while elapsed < timeout:
            time.sleep(interval)
            elapsed += interval
            try:
                data, res = self.get(
                    prompt_url,
                    raise_errors=False,
                    auto_login=False,
                    return_response=True,
                )
            except requests.exceptions.InvalidJSONError:
                # `requests.exceptions.JSONDecodeError` inherits from
                # `InvalidJSONError` which inherits from `RequestException`.
                # Without this explicit re-raise the broad catch below would
                # turn a malformed-payload shape error into a misleading
                # "network" retry, masking the real cause.
                raise
            except requests.RequestException as e:
                consecutive_failures += 1
                self.logger.error(
                    f"Prompt poll network error " f"({consecutive_failures}/3): {e}"
                )
                if consecutive_failures >= 3:
                    raise AuthenticationError(
                        f"Prompt polling failed after 3 consecutive errors: {e}"
                    ) from e
                continue
            # DoS-proofing: a persistent 5xx from the poll endpoint (no
            # RequestException raised, so we reach here) should still count
            # as a failure. Otherwise a timeout-never-raising upstream would
            # let us loop for the full `timeout` window, wasting cycles and
            # swallowing the real cause. Only reset the counter on a clean
            # 200 with a known status value.
            status_reset_ok = res.status_code == 200 and data.get(
                "challenge_status"
            ) in ("issued", "unknown")
            if res.status_code >= 500:
                consecutive_failures += 1
                self.logger.error(
                    "Prompt poll server error (%s/3): status=%s",
                    consecutive_failures,
                    res.status_code,
                )
                if consecutive_failures >= 3:
                    raise AuthenticationError(
                        f"Prompt polling failed after 3 consecutive "
                        f"server errors (last status={res.status_code})"
                    ) from None
            elif status_reset_ok:
                consecutive_failures = 0
            if res.status_code == 200:
                status = data.get("challenge_status", "unknown")
                self.logger.info(f"Prompt status: {status} ({elapsed}s)")
                if status == "validated":
                    return True
                if status in ("denied", "expired"):
                    raise AuthenticationError(f"Device approval {status}")
        raise AuthenticationError(f"Device approval timed out after {timeout}s")

    def _user_view_get(self, machine_id):
        request_url = urls.INQUIRIES / f"{machine_id}/user_view/"
        data, res = self.get(
            request_url, raise_errors=False, auto_login=False, return_response=True
        )
        if res.status_code != requests.codes.ok:
            self.logger.error("User View Error")
            raise AuthenticationError(
                f"User View Error: status={res.status_code} "
                f"body={_truncate_body(res)}"
            )
        sheriff_challenge = data["context"]["sheriff_challenge"]
        challenge_id = sheriff_challenge["id"]
        challenge_type = sheriff_challenge.get("type", "sms")
        return challenge_id, challenge_type

    def _user_view_post(self, machine_id):
        request_url = urls.INQUIRIES / f"{machine_id}/user_view/"
        payload = {"sequence": 0, "user_input": {"status": "continue"}}
        data, res = self.post(
            request_url,
            data=payload,
            raise_errors=False,
            auto_login=False,
            return_response=True,
        )
        if res.status_code != requests.codes.ok:
            # Previously the non-200 branch was "log and return False" which
            # the caller turned into a generic "MFA login workflow aborted"
            # error, hiding the real HTTP status. Surface it instead.
            raise AuthenticationError(
                f"User View POST HTTP status={res.status_code} "
                f"body={_truncate_body(res)}"
            ) from None
        if data["type_context"]["result"] == "workflow_status_approved":
            return True
        # 200 received but workflow was not approved — genuine denial signal.
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
        self.logger.info(
            f"login| self.oauth.is_valid: {self.oauth.is_valid}  \t  self.token_expired: {self.token_expired} \t force_refresh: {force_refresh}"
        )
        if "Authorization" not in self.session.headers:
            # No active Authorization header — need to establish a session
            if self.oauth and self.oauth.is_valid:
                # We have a token already; try refresh first
                try:
                    self._refresh_oauth2()
                except AuthenticationError as e:
                    if _is_permanent_refresh_failure(e):
                        # 401 / 403 / invalid_grant: token revoked, no point
                        # silently falling through to a password login — that
                        # would present as an unrelated MFA prompt. Surface
                        # the real auth denial instead.
                        raise
                    if self.login_set:
                        self.logger.warning(
                            "Refresh failed, falling back to password login",
                            exc_info=True,
                        )
                        self._login_oauth2()
                    else:
                        raise
                return
            elif self.login_set:
                self._login_oauth2()
            else:
                raise AuthenticationError(
                    "Valid auth token not sent and login credentials missing"
                )
        elif force_refresh or self.token_expired:
            # Already have Authorization header but token needs refreshing
            if self.oauth and self.oauth.is_valid:
                try:
                    self._refresh_oauth2()
                    return
                except AuthenticationError as e:
                    if _is_permanent_refresh_failure(e):
                        # Token revoked — surface the real cause with
                        # __cause__ preserved so callers can debug.
                        raise
                    self.logger.warning(
                        "Refresh failed, falling back to password login",
                        exc_info=True,
                    )
            if self.login_set:
                self._login_oauth2()
            else:
                raise AuthenticationError(
                    "Cannot refresh: no refresh token and no login credentials"
                )

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
        except HTTPError as e:
            err_res = getattr(e, "response", None)
            status = getattr(err_res, "status_code", "?")
            raise AuthenticationError(
                f"Could not log out: status={status} body={_truncate_body(err_res)}"
            ) from e

    @property
    def token_expired(self) -> bool:
        """Check if the issued auth token has expired.

        Returns:
            True if expired otherwise False
        """
        self.logger.info(f"token_expired| self.expires_at: {self.expires_at}")
        self.logger.info(
            f"token_expired| type(self.expires_at): {type(self.expires_at)}"
        )
        return pendulum.now(tz="UTC") > self.expires_at


class SessionManagerSchema(BaseSchema):
    """Schema class for the SessionManager model."""

    __model__ = SessionManager

    # Call untyped "Email" in typed context
    username = fields.Email()  # type: ignore
    password = fields.Str()
    challenge_type = fields.Str(validate=CHALLENGE_TYPE_VAL)
    oauth = fields.Nested(OAuthSchema)
    expires_at = fields.DateTime()
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
