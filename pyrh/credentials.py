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
    return Path(os.environ.get("PYRH_CREDENTIALS_FILE", str(_DEFAULT_CREDENTIALS_PATH)))


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
    except OSError:
        logger.warning("Cannot fix permissions on %s", path)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise CredentialsFileCorruptError(path, f"JSON parse error: {exc}") from None
    except OSError as exc:
        raise CredentialsFileCorruptError(path, f"OS error: {exc}") from None


def write_tokens(data: dict) -> None:
    """Write tokens to credentials file atomically at 0600.

    Creates a temp file with 0600 permissions from the start (no world-readable
    window), then atomically renames over the target. Cleans up temp on failure.
    """
    path = get_credentials_path()
    path.parent.mkdir(parents=True, exist_ok=True)
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
        if tmp.exists():
            tmp.unlink()
        raise


def delete_tokens() -> None:
    """Delete credentials file (no-op if absent)."""
    path = get_credentials_path()
    if path.exists():
        path.unlink()
        logger.info("Credentials file deleted: %s", path)


def revoke_session() -> None:
    """Revoke stored tokens at Robinhood API then delete locally.

    Best-effort API revocation: if the credentials file is corrupt or the
    network call fails, we still delete the local file.
    """
    import requests
    from pyrh.constants import CLIENT_ID

    try:
        cached = read_tokens()
    except CredentialsFileCorruptError as exc:
        logger.warning("Cannot read credentials for API revocation (%s); deleting anyway.", exc.reason)
        cached = None

    if cached and "access_token" in cached:
        try:
            requests.post(
                "https://api.robinhood.com/oauth2/revoke_token/",
                json={"client_id": CLIENT_ID, "token": cached["access_token"]},
                timeout=10,
            )
        except Exception as exc:
            logger.warning("API token revocation failed (token may still be live): %s", exc)

    delete_tokens()
    logger.critical("SESSION REVOKED: credentials file deleted")
