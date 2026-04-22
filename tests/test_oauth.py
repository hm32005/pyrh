# coding=utf-8
"""Test the oauth classes."""

from freezegun import freeze_time


@freeze_time("2020-01-01")
def test_challenge_can_retry():
    from datetime import datetime, timedelta

    import pytz

    from pyrh.models.oauth import Challenge

    future = datetime.strptime("2020-01-02", "%Y-%m-%d").replace(tzinfo=pytz.UTC)

    # The ChallengeSchema field is `expires_at` (AwareDateTime) — matching
    # the Robinhood wire payload — and can_retry compares against
    # ``self.expires_at``. A prior rename to ``expires_in`` dropped the
    # wire field entirely; keep the assertions in terms of the wire name.
    data = {"expires_at": future}

    challenge = Challenge(**data)

    assert not challenge.can_retry

    challenge.remaining_attempts = 1
    assert challenge.can_retry

    challenge.expires_at = future - timedelta(days=3)

    assert not challenge.can_retry


def test_oauth_test_attrs():
    from pyrh.models.base import UnknownModel
    from pyrh.models.oauth import OAuth

    oa = OAuth()
    oa.challenge = UnknownModel(a="test")
    assert oa.is_challenge

    oa.mfa_required = UnknownModel(a="test")
    assert oa.is_mfa

    oa.access_token = "some-token"
    oa.refresh_token = "other-token"
    assert oa.is_valid


@freeze_time("2020-01-01")
def test_oauth_init_derives_expires_in_from_expires_at():
    """Passing expires_at to OAuth() causes expires_in to be the diff in seconds."""
    import pendulum

    from pyrh.models.oauth import OAuth

    future = pendulum.datetime(2020, 1, 2, tz="UTC")
    oauth = OAuth(access_token="t", refresh_token="r", expires_at=future)

    # Exactly 24 hours from the frozen now.
    assert oauth.expires_in == 86400
    assert oauth.access_token == "t"
    assert oauth.refresh_token == "r"


def test_challenge_schema_loads_wire_payload_with_expires_at():
    """ChallengeSchema must accept Robinhood's real wire shape.

    Robinhood's 401 challenge response ships an ``expires_at`` (ISO datetime)
    field on the challenge object — separate from ``OAuth.expires_in`` (an
    integer TTL in seconds on the token response). A rename to ``expires_in``
    on the Challenge schema dropped the wire field, so ``can_retry`` later
    raised ``AttributeError: 'Challenge' object has no attribute 'expires_in'``.
    """
    import uuid

    from pyrh.models.oauth import Challenge, ChallengeSchema

    payload = {
        "id": str(uuid.uuid4()),
        "user": str(uuid.uuid4()),
        "type": "email",
        "alternate_type": "sms",
        "status": "issued",
        "remaining_retries": 3,
        "remaining_attempts": 3,
        "expires_at": "2026-04-22T12:00:00+00:00",
    }

    challenge = ChallengeSchema().load(payload)

    assert isinstance(challenge, Challenge)
    assert hasattr(challenge, "expires_at"), (
        "ChallengeSchema dropped the expires_at wire field"
    )
    # Sanity check can_retry doesn't raise AttributeError.
    assert isinstance(challenge.can_retry, bool)


def test_oauth_expires_in_stays_distinct_from_challenge_expires_at():
    """Challenge.expires_at (datetime) and OAuth.expires_in (seconds int) are separate wire fields."""
    from pyrh.models.oauth import OAuthSchema

    token_payload = {
        "access_token": "at",
        "refresh_token": "rt",
        "expires_in": 3600,
    }
    oauth = OAuthSchema().load(token_payload)
    assert oauth.expires_in == 3600


def test_oauth_init_does_not_log_token_values_at_info(caplog):
    """Guardrail: OAuth() must not emit access_token / refresh_token values at INFO or higher."""
    import logging

    from pyrh.models.oauth import OAuth

    # DEBUG-level capture is required: the fix's stated guarantee is that
    # tokens never appear in any log record at any level. INFO-only capture
    # would silently miss a regression that logs tokens at DEBUG.
    caplog.set_level(logging.DEBUG, logger="pyrh.models.oauth")
    OAuth(access_token="SECRET_AT", refresh_token="SECRET_RT")

    joined = "\n".join(rec.getMessage() for rec in caplog.records)
    assert "SECRET_AT" not in joined
    assert "SECRET_RT" not in joined
