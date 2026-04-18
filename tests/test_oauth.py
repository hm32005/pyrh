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
