# coding=utf-8
"""Tests for pyrh.credentials — the token storage layer.

Covers: get_credentials_path, read_tokens, write_tokens, delete_tokens,
CredentialsFileCorruptError. revoke_session is excluded because it makes
live HTTP calls to Robinhood (network dependency).
"""
import json
import os
from pathlib import Path

import pytest

from pyrh.credentials import (
    CredentialsFileCorruptError,
    delete_tokens,
    get_credentials_path,
    read_tokens,
    write_tokens,
)

SAMPLE = {
    "access_token": "tok-access",
    "refresh_token": "tok-refresh",
    "device_token": "dev-123",
    "expires_at": "2026-04-30T22:19:03+00:00",
    "version": 1,
}


# ---------------------------------------------------------------------------
# get_credentials_path
# ---------------------------------------------------------------------------


def test_get_credentials_path_default_is_pyrh_home(monkeypatch):
    monkeypatch.delenv("PYRH_CREDENTIALS_FILE", raising=False)
    path = get_credentials_path()
    assert path == Path.home() / ".pyrh" / "credentials.json"


def test_get_credentials_path_overridable_via_env(tmp_path, monkeypatch):
    override = str(tmp_path / "custom.json")
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", override)
    assert get_credentials_path() == Path(override)


# ---------------------------------------------------------------------------
# read_tokens
# ---------------------------------------------------------------------------


def test_read_tokens_returns_none_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    assert read_tokens() is None


def test_read_tokens_returns_written_dict(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    write_tokens(SAMPLE)
    assert read_tokens() == SAMPLE


def test_read_tokens_raises_corrupt_error_on_bad_json(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    creds.write_text("{ not valid json !!!")
    creds.chmod(0o600)
    with pytest.raises(CredentialsFileCorruptError):
        read_tokens()


def test_read_tokens_raises_corrupt_error_on_empty_file(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    creds.write_text("")
    creds.chmod(0o600)
    with pytest.raises(CredentialsFileCorruptError):
        read_tokens()


# ---------------------------------------------------------------------------
# write_tokens
# ---------------------------------------------------------------------------


def test_write_tokens_creates_file(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    write_tokens(SAMPLE)
    assert creds.exists()


def test_write_tokens_sets_0600_permissions(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    write_tokens(SAMPLE)
    assert (creds.stat().st_mode & 0o777) == 0o600


def test_write_tokens_contains_valid_json(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    write_tokens(SAMPLE)
    parsed = json.loads(creds.read_text())
    assert parsed["access_token"] == "tok-access"


def test_write_tokens_leaves_no_tmp_file(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    write_tokens(SAMPLE)
    assert not (tmp_path / "creds.json.tmp").exists()


def test_write_tokens_creates_parent_dirs(tmp_path, monkeypatch):
    creds = tmp_path / "deep" / "nested" / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    write_tokens(SAMPLE)
    assert creds.exists()


# ---------------------------------------------------------------------------
# delete_tokens
# ---------------------------------------------------------------------------


def test_delete_tokens_removes_file(tmp_path, monkeypatch):
    creds = tmp_path / "creds.json"
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(creds))
    write_tokens(SAMPLE)
    delete_tokens()
    assert not creds.exists()


def test_delete_tokens_is_noop_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(tmp_path / "creds.json"))
    delete_tokens()  # must not raise


# ---------------------------------------------------------------------------
# read_tokens — directory-path guard (regression)
# ---------------------------------------------------------------------------


def test_read_tokens_refuses_directory_path(tmp_path, monkeypatch):
    """If PYRH_CREDENTIALS_FILE is misconfigured to a directory, read_tokens
    must raise CredentialsFileCorruptError BEFORE chmod runs — otherwise it
    would strip the directory's execute bit and break traversal of any tree
    that contained it (real incident at ~/Personal/code/investment-system,
    Apr 28-29 / May 1).
    """
    monkeypatch.setenv("PYRH_CREDENTIALS_FILE", str(tmp_path))
    pre_mode = tmp_path.stat().st_mode & 0o777

    with pytest.raises(CredentialsFileCorruptError):
        read_tokens()

    # Directory's mode must be unchanged — proves chmod path was NOT reached.
    post_mode = tmp_path.stat().st_mode & 0o777
    assert post_mode == pre_mode, (
        f"directory mode changed from {oct(pre_mode)} to {oct(post_mode)} — "
        f"chmod ran on a directory, regression!"
    )
    # And specifically: not 0o600 (the bug's failure mode).
    assert post_mode != 0o600, (
        "directory was chmoded to 0o600 — the chmod-on-directory bug returned"
    )
