#!/usr/bin/env python3
"""
Robinhood Authentication CLI (like gcpfed / gcloud auth login)

Human-driven authentication for any pyrh-based application.
Password is read via getpass (never stored, never in shell args or history).
Tokens are saved to ~/.pyrh/credentials.json — the single canonical token
store. Downstream consumers (investment-system, robinhood-data-downloader)
read from this path directly.

Usage:
    python scripts/robinhood_login.py            # authenticate (interactive)
    python scripts/robinhood_login.py --status    # check token health
    python scripts/robinhood_login.py --revoke    # revoke all tokens
    python scripts/robinhood_login.py --where     # print credentials file path

SAFETY: This script ONLY authenticates. It never places orders.
"""

import argparse
import getpass
import json
import logging
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    print("ERROR: requests required. pip install requests")
    sys.exit(1)

from pyrh.constants import CLIENT_ID, EXPIRATION_TIME
from pyrh import urls
from pyrh.credentials import (
    CredentialsFileCorruptError,
    read_tokens,
    write_tokens,
    get_credentials_path,
    revoke_session,
)


def login() -> bool:
    """Interactive login — password via getpass, tokens saved to file."""
    print("\n  Robinhood Authentication")
    print("  " + "=" * 40)

    # Read credentials securely — NEVER in shell args or history
    username = input("  Email: ").strip()
    password = getpass.getpass("  Password: ")

    print()
    logger.info("Authenticating as %s...", username[:3] + "***")

    # Reuse existing device token if available, otherwise create one.
    # A corrupt credentials file just means "start fresh" here since we're
    # about to overwrite it with a new login anyway.
    try:
        existing = read_tokens()
    except CredentialsFileCorruptError as exc:
        logger.warning(
            "Existing credentials file is corrupt (%s); starting fresh login.",
            exc.reason,
        )
        print(
            f"  WARNING: existing credentials file is corrupt ({exc.reason}); "
            "starting fresh login.",
            file=sys.stderr,
        )
        existing = None
    device_token = (existing or {}).get("device_token") or str(uuid.uuid4())

    session = requests.Session()
    session.headers["Content-Type"] = "application/json"
    session.headers["User-Agent"] = "pyrh/2.2.0 (Personal Use)"

    # Step 1: OAuth
    res = session.post(str(urls.OAUTH), json={
        "client_id": CLIENT_ID,
        "create_read_only_secondary_token": True,
        "device_token": device_token,
        "expires_in": EXPIRATION_TIME,
        "grant_type": "password",
        "password": password,
        "request_id": str(uuid.uuid4()),
        "scope": "internal",
        "token_request_path": "/login",
        "username": username,
    }, timeout=30)

    # Discard password immediately — never stored anywhere
    del password

    body = res.json()
    if res.status_code != 403 or "verification_workflow" not in body:
        logger.error("Auth failed: %s", res.status_code)
        return False

    workflow_id = body["verification_workflow"]["id"]
    oauth_payload = json.loads(res.request.body)

    # Step 2: Machine + Challenge
    session.headers["Content-Type"] = "application/json"
    res = session.post(str(urls.USER_MACHINE), json={
        "device_id": device_token, "flow": "suv",
        "input": {"workflow_id": workflow_id},
    }, timeout=30)
    machine_id = res.json()["id"]

    user_view_url = f"https://api.robinhood.com/pathfinder/inquiries/{machine_id}/user_view/"
    res = session.get(user_view_url, timeout=30)
    challenge_id = res.json()["context"]["sheriff_challenge"]["id"]

    # Step 3: Device approval
    print("\n  *** APPROVE THE LOGIN ON YOUR ROBINHOOD APP ***\n")
    for i in range(30):
        time.sleep(5)
        res = session.get(
            f"https://api.robinhood.com/push/{challenge_id}/get_prompts_status/",
            timeout=30,
        )
        if res.status_code == 200:
            status = res.json().get("challenge_status", "unknown")
            logger.info("  [%ds] %s", i * 5, status)
            if status == "validated":
                break
            if status in ("denied", "expired"):
                logger.error("Device approval %s", status)
                return False
    else:
        logger.error("Device approval timed out (150s)")
        return False

    # Step 4: Finalize
    res = session.post(user_view_url, json={
        "sequence": 0, "user_input": {"status": "continue"},
    }, timeout=30)
    if res.json().get("type_context", {}).get("result") != "workflow_status_approved":
        logger.error("Workflow not approved")
        return False

    # Step 5: Get token
    res = session.post(str(urls.OAUTH), json=oauth_payload, timeout=30)
    if res.status_code != 200:
        logger.error("Final auth failed: %s", res.status_code)
        return False

    token_data = res.json()

    if "access_token" not in token_data:
        logger.error(
            "Authentication response missing access_token. Keys: %s",
            list(token_data.keys()),
        )
        return False

    expires_in = token_data.get("expires_in", 648000)
    token_data["version"] = 1
    token_data["device_token"] = device_token
    token_data["expires_at"] = (
        datetime.now(tz=timezone.utc) + timedelta(seconds=expires_in)
    ).isoformat()
    token_data["created_at"] = datetime.now(tz=timezone.utc).isoformat()

    del oauth_payload

    # Write to pyrh canonical path
    try:
        write_tokens(token_data)
    except OSError as exc:
        logger.error("Authentication succeeded but tokens could NOT be saved: %s", exc)
        print(f"\n  ERROR: Could not save tokens to {get_credentials_path()}")
        print(f"  Cause: {exc}")
        print(f"  Fix: Check disk space and directory permissions, then re-authenticate.\n")
        return False

    logger.info(
        "Authenticated successfully. Token expires in %.1f days.",
        expires_in / 86400,
    )

    # Verify with a lightweight API call
    session.headers["Authorization"] = f"Bearer {token_data['access_token']}"
    test = session.get("https://api.robinhood.com/portfolios/", timeout=10)
    if test.status_code == 200:
        equity = test.json().get("results", [{}])[0].get("equity", "?")
        logger.info("Portfolio equity: $%s", equity)

    cred_path = get_credentials_path()
    print(f"\n  Authentication complete.")
    print(f"  Credentials: {cred_path}")
    print(f"  All scripts will use this token automatically.\n")
    return True


def check_status() -> None:
    """Check current authentication status."""
    print("\n  Token Status")
    print("  " + "=" * 40)

    cred_path = get_credentials_path()
    print(f"  File: {cred_path}")

    try:
        cached = read_tokens()
    except CredentialsFileCorruptError as exc:
        print("  Status: CREDENTIALS FILE CORRUPT")
        print(f"  Reason: {exc.reason}")
        print("  Fix: delete or repair the file, then:")
        print("       python scripts/robinhood_login.py")
        return
    if not cached or "access_token" not in cached:
        print("  Status: NOT AUTHENTICATED")
        print("  Run: python scripts/robinhood_login.py")
        return

    if cred_path.exists():
        mtime = datetime.fromtimestamp(cred_path.stat().st_mtime, tz=timezone.utc)
        print(f"  Last updated: {mtime.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    expires_at = cached.get("expires_at", "")
    if expires_at:
        exp = datetime.fromisoformat(str(expires_at))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        remaining = exp - now
        hours = remaining.total_seconds() / 3600
        days = hours / 24

        if remaining.total_seconds() > 0:
            print(f"  Status: AUTHENTICATED")
            print(f"  Expires: {expires_at[:19]} ({days:.1f} days remaining)")
        else:
            print(f"  Status: EXPIRED ({abs(days):.1f} days ago)")
            print(f"  Run: python scripts/robinhood_login.py")
    else:
        print("  Status: AUTHENTICATED (no expiry data)")

    session = requests.Session()
    session.headers["Authorization"] = f"Bearer {cached['access_token']}"
    session.headers["User-Agent"] = "pyrh/2.2.0 (Personal Use)"
    try:
        res = session.get("https://api.robinhood.com/user/", timeout=10)
        if res.status_code == 200:
            print(f"  API: REACHABLE")
        else:
            print(f"  API: UNREACHABLE (status {res.status_code})")
            print(f"  Token may need refresh. Run: python scripts/robinhood_login.py")
    except requests.RequestException as e:
        print(f"  API: CONNECTION ERROR ({e})")


def revoke() -> None:
    """Revoke all stored tokens."""
    print("\n  Revoking Tokens")
    print("  " + "=" * 40)

    try:
        revoke_session()
        print("  All tokens revoked and credentials file deleted.")
    except Exception as e:
        print(f"  Revocation error: {e}")

    print()


def where() -> None:
    """Print the credentials file path."""
    cred_path = get_credentials_path()
    print(f"{cred_path}")
    if cred_path.exists():
        mode = oct(cred_path.stat().st_mode & 0o777)
        print(f"  exists, permissions: {mode}")
    else:
        print("  (does not exist — run: python scripts/robinhood_login.py)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Robinhood Authentication CLI",
        epilog="Like gcpfed/gcloud auth — human-driven auth, automatic token refresh.",
    )
    parser.add_argument("--status", action="store_true", help="Check token health")
    parser.add_argument("--revoke", action="store_true", help="Revoke all tokens (emergency)")
    parser.add_argument("--where", action="store_true", help="Print credentials file path")
    args = parser.parse_args()

    if args.status:
        check_status()
    elif args.revoke:
        revoke()
    elif args.where:
        where()
    else:
        login()


if __name__ == "__main__":
    main()
