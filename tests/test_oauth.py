# coding=utf-8
"""Test the oauth classes."""

from freezegun import freeze_time


@freeze_time("2020-01-01")
def test_challenge_can_retry():
    from datetime import datetime, timedelta

    import pytz

    from pyrh.models.oauth import Challenge

    future = datetime.strptime("2020-01-02", "%Y-%m-%d").replace(tzinfo=pytz.UTC)

    # The ChallengeSchema field is `expires_in` (AwareDateTime), and
    # can_retry compares against `self.expires_in`.
    data = {"expires_in": future}

    challenge = Challenge(**data)

    assert not challenge.can_retry

    challenge.remaining_attempts = 1
    assert challenge.can_retry

    challenge.expires_in = future - timedelta(days=3)

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
