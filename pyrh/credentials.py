# coding=utf-8
"""Token storage for Robinhood credentials.

Manages ~/.pyrh/credentials.json (0600) — the canonical token store for pyrh.
Path is configurable via PYRH_CREDENTIALS_FILE env var (used in tests).

Functions:
    get_credentials_path — returns the active credentials file path
    read_tokens          — returns the stored dict, or None if no file
    write_tokens         — atomic 0600 write
    delete_tokens        — removes the file (no-op if absent)
    revoke_session       — revokes token at Robinhood API + deletes locally
"""
import json
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DEFAULT_CREDENTIALS_PATH = Path.home() / ".pyrh" / "credentials.json"


class CredentialsFileCorruptError(RuntimeError):
    """Credentials file exists but cannot be parsed (truncated, bad JSON, empty).

    Attributes:
        path: The filesystem path that was unparseable.
        reason: The underlying parse error message.
    """

    def __init__(self, path: Path, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(
            f"Credentials file at {path} is unparseable: {reason}. "
            f"Delete or repair, then re-authenticate: python -m pyrh.scripts.robinhood_login"
        )


def get_credentials_path() -> Path:
    """Return the active credentials file path (env-overridable for tests)."""
    # `or` (not just default) so an empty PYRH_CREDENTIALS_FILE="" falls back
    # to the default. Path("") resolves to Path(".") (CWD), which would cause
    # write_tokens to write a `.tmp` into CWD and rename to "." — destructive.
    return Path(os.environ.get("PYRH_CREDENTIALS_FILE") or str(_DEFAULT_CREDENTIALS_PATH))


def read_tokens() -> Optional[dict]:
    """Read tokens from credentials file.

    Returns:
        The decoded token dict, or None if the file does not exist.

    Raises:
        CredentialsFileCorruptError: File exists but is malformed.
    """
    path = get_credentials_path()
    if not path.exists():
        return None
    # SECURITY: Refuse to chmod anything that's not a regular file. If
    # PYRH_CREDENTIALS_FILE is misconfigured to a directory (e.g., a test
    # fixture passing tmp_path instead of tmp_path / "creds.json"), the
    # chmod below would strip the directory's execute bit and break
    # traversal. The is_file() check refuses early with a clear error
    # rather than damaging the filesystem.
    if not path.is_file():
        raise CredentialsFileCorruptError(
            path, f"credentials path is not a regular file: {path}"
        )
    try:
        current_mode = path.stat().st_mode & 0o777
        if current_mode != 0o600:
            os.chmod(path, 0o600)
    except OSError as exc:
        # SECURITY: Don't silently proceed with insecure perms. The function's
        # contract is "tokens at 0o600"; if we can't enforce it, refuse to
        # return the tokens — otherwise callers operate on insecure creds
        # without any signal.
        logger.warning("Cannot enforce 0o600 on %s: %s", path, exc)
        raise CredentialsFileCorruptError(path, f"cannot enforce 0o600: {exc}") from None
    try:
        result = json.loads(path.read_text())
    # SECURITY: from None — JSONDecodeError.doc carries the file's raw content
    # (i.e., the access/refresh tokens). Chaining via `from exc` would leak
    # tokens into tracebacks rendered by Sentry / traceback.format_exception().
    # DO NOT change to `from exc`.
    except json.JSONDecodeError as exc:
        raise CredentialsFileCorruptError(path, f"JSON parse error: {exc}") from None
    except OSError as exc:
        raise CredentialsFileCorruptError(path, f"OS error: {exc}") from None
    if not isinstance(result, dict):
        # `null`, `[]`, `"string"`, `42` would otherwise round-trip back to
        # callers as non-dict and fail downstream with a confusing TypeError
        # at `cached["access_token"]`. Detect early.
        raise CredentialsFileCorruptError(
            path, f"expected JSON object, got {type(result).__name__}"
        )
    return result


def write_tokens(data: dict) -> None:
    """Write tokens to credentials file atomically at 0600.

    Creates a temp file with 0600 permissions from the start (no world-readable
    window), then atomically renames over the target. Cleans up temp on failure.
    """
    path = get_credentials_path()
    # mode=0o700 prevents presence-disclosure on multi-user hosts. The mode
    # arg is ignored if the dir already exists, so chmod explicitly to be
    # idempotent on existing dirs.
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path.parent, 0o700)
    except OSError as exc:
        logger.warning("Cannot tighten %s to 0o700: %s", path.parent, exc)
    tmp = path.with_name(path.name + ".tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
            f.flush()
            os.fsync(f.fileno())
        tmp.rename(path)
        logger.info("Tokens written to %s", path)
    except Exception:
        # Cleanup is best-effort and must NOT mask the original exception.
        # A bare `tmp.unlink()` here would replace the original error if the
        # unlink itself raised (concurrent unlink / EBUSY).
        try:
            tmp.unlink(missing_ok=True)
        except OSError as cleanup_exc:
            logger.warning("Failed to clean up tmp file %s: %s", tmp, cleanup_exc)
        raise


def delete_tokens() -> None:
    """Delete credentials file (no-op if absent)."""
    path = get_credentials_path()
    # missing_ok=True avoids the TOCTOU race between exists() and unlink()
    # that would otherwise contradict the "no-op if absent" docstring.
    try:
        path.unlink(missing_ok=True)
    except IsADirectoryError:
        # Defense consistency with read_tokens's is_file() guard: refuse to
        # operate on a directory (likely env var misconfiguration).
        raise CredentialsFileCorruptError(
            path, f"credentials path is not a regular file: {path}"
        )
    else:
        logger.info("Credentials file deleted (or absent): %s", path)


def revoke_session() -> bool:
    """Revoke stored tokens at Robinhood API then delete locally.

    Returns:
        True iff server-side revocation was confirmed (HTTP 2xx) AND the
        local file was deleted. False means the API call failed or returned
        non-2xx — token may still be live; the local file is NOT deleted in
        that case so the user can retry.

    Behavior on corrupt local file: deletes the local file but skips the
    API call (we have no token to send) and returns False.
    """
    import requests
    from pyrh.constants import CLIENT_ID

    try:
        cached = read_tokens()
    except CredentialsFileCorruptError as exc:
        logger.warning(
            "Cannot read credentials for API revocation (%s); deleting local file only.",
            exc.reason,
        )
        delete_tokens()
        return False

    if not cached or "access_token" not in cached:
        # No server-side token to revoke; clean up local state.
        delete_tokens()
        return False

    try:
        resp = requests.post(
            "https://api.robinhood.com/oauth2/revoke_token/",
            json={"client_id": CLIENT_ID, "token": cached["access_token"]},
            timeout=10,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        # SECURITY: Do NOT delete locally if we couldn't confirm server-side
        # revocation. Otherwise the user thinks the session is revoked but
        # an attacker holding the token can still trade. Surface the failure
        # so the caller can retry or instruct the user to revoke via the
        # Robinhood website.
        logger.error(
            "Server-side revocation FAILED — token may still be live. "
            "Local credentials NOT deleted. Retry, or revoke via robinhood.com. Error: %s",
            exc,
        )
        return False

    delete_tokens()
    logger.info("Session revoked: server confirmed + local credentials deleted.")
    return True
