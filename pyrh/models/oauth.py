"""Oauth models."""
import logging
from datetime import datetime
from typing import Any

import pendulum
import pytz
from marshmallow import fields, validate

from .base import BaseModel, BaseSchema

CHALLENGE_TYPE_VAL = validate.OneOf(["email", "sms"])


class Challenge(BaseModel):
    """The challenge response model."""

    remaining_attempts = 0
    """Default `remaining_attempts` attribute if it is not set on instance."""

    @property
    def can_retry(self) -> bool:
        """Determine if the challenge can be retried.

        Returns:
            True if remaining_attempts is greater than zero and challenge is not \
                expired, False otherwise.

        """
        return self.remaining_attempts > 0 and (
                datetime.now(tz=pytz.utc) < self.expires_in
        )


class ChallengeSchema(BaseSchema):
    """The challenge response schema."""

    __model__ = Challenge

    id = fields.UUID()
    user = fields.UUID()
    type = fields.Str(validate=CHALLENGE_TYPE_VAL)
    alternate_type = fields.Str(
        validate=CHALLENGE_TYPE_VAL, required=False, allow_none=True
    )
    status = fields.Str(validate=validate.OneOf(["issued", "validated", "failed"]))
    remaining_retries = fields.Int()
    remaining_attempts = fields.Int()
    expires_in = fields.AwareDateTime(default_timezone=pytz.UTC)  # type: ignore


class OAuth(BaseModel):
    """The OAuth response model."""

    def __init__(self, **kwargs: Any):
        super().__init__(**kwargs)
        self.__logger = logging.getLogger(__name__)
        if "access_token" in kwargs:
            self.access_token = kwargs["access_token"]
            self.logger.info(f"OAuth init| access_token: {kwargs['access_token']}")
        if "refresh_token" in kwargs:
            self.refresh_token = kwargs["refresh_token"]
            self.logger.info(f"OAuth init| refresh_token {kwargs['refresh_token']}")
        if "expires_at" in kwargs:
            self.expires_in = pendulum.parse(kwargs["expires_at"]).diff(pendulum.now(tz="UTC")).in_seconds()
            self.logger.info(f"OAuth init| expires_in: {self.expires_in} \t expires_at: {kwargs['expires_at']}")

    @property
    def logger(self):
        return self.__logger

    @property
    def is_challenge(self) -> bool:
        """Determine whether the oauth response is a challenge.

        Returns:
            True response has the `challenge` key, False otherwise.

        """
        return hasattr(self, "challenge")

    @property
    def is_mfa(self) -> bool:
        """Determine whether the oauth response is a mfa challenge.

        Returns:
            True response has the `mfa_required` key, False otherwise.

        """
        return hasattr(self, "mfa_required")

    @property
    def is_valid(self) -> bool:
        """Determine whether the oauth response is a valid response.

        Returns:
            True if the response has both the `access_token` and `refresh_token` keys, \
                False otherwise.

        """
        return hasattr(self, "access_token") and hasattr(self, "refresh_token")


class OAuthSchema(BaseSchema):
    """The OAuth response schema."""

    __model__ = OAuth

    detail = fields.Str()
    challenge = fields.Nested(ChallengeSchema)
    mfa_required = fields.Boolean()

    access_token = fields.Str()
    refresh_token = fields.Str()
    expires_in = fields.Int()
