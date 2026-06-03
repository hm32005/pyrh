#!/usr/bin/env python3
"""
Robinhood Authentication CLI (like gcpfed / gcloud auth login)

Opens robinhood.com/login in a real browser window. You log in normally
(including reCAPTCHA and app approval). The script intercepts the OAuth
token response and saves it to ~/.pyrh/credentials.json.

Why a browser? Robinhood added reCAPTCHA (gr_key/gr_token) to the password
login endpoint in 2025. Scripts cannot generate reCAPTCHA tokens without a
real browser runtime. Once bootstrapped, the daily refresh_auth_token DAG
uses grant_type=refresh_token which does NOT require reCAPTCHA.

Usage:
    python scripts/robinhood_login.py            # authenticate (interactive)
    python scripts/robinhood_login.py --status    # check token health
    python scripts/robinhood_login.py --revoke    # revoke all tokens
    python scripts/robinhood_login.py --where     # print credentials file path

SAFETY: This script ONLY authenticates. It never places orders.
"""

import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    print("ERROR: requests required. pip install requests")
    sys.exit(1)

from pyrh.credentials import (
    CredentialsFileCorruptError,
    read_tokens,
    write_tokens,
    get_credentials_path,
    revoke_session,
)
from pyrh.util import robinhood_headers


_PROFILE_DIR = Path.home() / ".pyrh" / "chromium_profile"
_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36"
)


def _intercept_token(page) -> dict:
    """Attach a response listener and return the first OAuth token response seen."""
    try:
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError:
        return {}

    token_data = {}

    def handle_response(response):
        if "/oauth2/token/" in response.url and not token_data:
            try:
                body = response.json()
                if "access_token" in body:
                    token_data.update(body)
                    logger.info("Token captured from browser response.")
            except Exception:
                pass

    page.on("response", handle_response)
    return token_data


def _write_token(token_data: dict) -> bool:
    """Enrich token_data with metadata and write to credentials file. Returns success."""
    now = datetime.now(tz=timezone.utc)
    expires_in = token_data.get("expires_in", 86400)
    token_data.setdefault("expires_at", (now + timedelta(seconds=expires_in)).isoformat())
    token_data["created_at"] = now.isoformat()
    token_data["version"] = 1

    try:
        existing = read_tokens()
    except (CredentialsFileCorruptError, Exception):
        existing = {}
    if existing and existing.get("device_token") and "device_token" not in token_data:
        token_data["device_token"] = existing["device_token"]

    try:
        write_tokens(token_data)
    except OSError as exc:
        logger.error("Could not save tokens: %s", exc)
        return False

    logger.info("Authenticated. Token expires in %.1f days.", expires_in / 86400)

    session = requests.Session()
    session.headers.update(robinhood_headers)
    session.headers["Authorization"] = f"Bearer {token_data['access_token']}"
    try:
        test = session.get("https://api.robinhood.com/portfolios/", timeout=10)
        if test.status_code == 200:
            equity = test.json().get("results", [{}])[0].get("equity", "?")
            print(f"  Portfolio equity: ${equity}")
            return True
        elif test.status_code in (401, 403):
            logger.error("Token rejected by API (HTTP %s) — deleting.", test.status_code)
            get_credentials_path().unlink(missing_ok=True)
            return False
        else:
            logger.warning("API verify returned HTTP %s.", test.status_code)
            return True
    except requests.RequestException as exc:
        logger.warning("Could not verify token against API (%s).", exc)
        return True


def refresh_headless() -> bool:
    """Silently refresh token using saved browser profile (no user interaction).

    Robinhood's web app auto-renews the session when the page loads. We intercept
    the /oauth2/token/ response in a headless browser with the saved profile.

    Returns True if a fresh token was captured and written, False otherwise.
    Callers should fall back to login() if this returns False.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        logger.error("playwright not installed. Run: pip install playwright && playwright install chromium")
        return False

    if not _PROFILE_DIR.exists():
        logger.info("No saved browser profile — run login() first.")
        return False

    token_data = {}
    logger.info("Attempting headless token refresh via saved browser profile...")

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            str(_PROFILE_DIR),
            headless=True,
            user_agent=_USER_AGENT,
            args=["--disable-blink-features=AutomationControlled"],
        )
        page = context.pages[0] if context.pages else context.new_page()
        captured = _intercept_token(page)

        try:
            page.goto("https://robinhood.com/", wait_until="domcontentloaded", timeout=20000)
        except Exception:
            pass

        # Wait up to 15s for token to appear
        deadline = datetime.now(timezone.utc) + timedelta(seconds=15)
        while not captured and datetime.now(timezone.utc) < deadline:
            try:
                page.wait_for_function("() => false", timeout=1000)
            except Exception:
                pass
        token_data.update(captured)
        context.close()

    if not token_data:
        logger.info("Headless refresh: no token captured (session may be expired).")
        return False

    return _write_token(token_data)


def login() -> bool:
    """Open robinhood.com/login in a visible browser. User logs in manually.

    Robinhood added reCAPTCHA in 2025 — scripts cannot satisfy it headlessly
    without a saved session. This interactive flow:
      1. Opens Chromium with the persistent profile (~/.pyrh/chromium_profile/)
      2. You log in at robinhood.com (reCAPTCHA + app approval happen naturally)
      3. Token is intercepted automatically; browser closes; profile is saved

    After one successful login(), refresh_headless() can renew silently forever
    as long as the browser profile's session cookies remain valid.
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        print("ERROR: playwright required. Run: pip install playwright && playwright install chromium")
        sys.exit(1)

    print("\n  Robinhood Authentication")
    print("  " + "=" * 40)
    print("  A browser window will open. Log in normally at robinhood.com.")
    print("  The script captures tokens automatically after you approve the login.")
    print("  Do NOT close the browser — it closes itself after tokens are captured.\n")

    _PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    token_data = {}

    with sync_playwright() as p:
        # Persistent context saves cookies/session so refresh_headless() works later
        context = p.chromium.launch_persistent_context(
            str(_PROFILE_DIR),
            headless=False,
            slow_mo=50,
            viewport={"width": 1280, "height": 800},
            user_agent=_USER_AGENT,
            args=["--disable-blink-features=AutomationControlled"],
        )
        page = context.pages[0] if context.pages else context.new_page()
        captured = _intercept_token(page)

        page.goto("https://robinhood.com/login", wait_until="domcontentloaded")
        print("  Waiting for you to log in (timeout: 5 minutes)...")

        deadline = datetime.now(timezone.utc) + timedelta(minutes=5)
        while not captured and datetime.now(timezone.utc) < deadline:
            try:
                page.wait_for_function("() => false", timeout=2000)
            except Exception:
                pass
        token_data.update(captured)
        context.close()

    if not token_data:
        logger.error("No token captured within 5 minutes. Did you complete the login?")
        return False

    ok = _write_token(token_data)
    if ok:
        print(f"  Credentials: {get_credentials_path()}")
        print(f"  Profile saved: {_PROFILE_DIR}")
        print(f"  Future refreshes will be fully automatic (no browser window).\n")
    return ok


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

    created_at = cached.get("created_at", "")
    if created_at:
        print(f"  Last updated: {created_at[:19]} UTC")

    expires_at = cached.get("expires_at", "")
    exp = None
    if expires_at:
        try:
            exp = datetime.fromisoformat(str(expires_at))
        except ValueError:
            print("  Status: AUTHENTICATED (expires_at unreadable — re-auth recommended)")

    if exp is not None:
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        remaining = exp - now
        days = remaining.total_seconds() / 86400
        if remaining.total_seconds() > 0:
            print(f"  Status: AUTHENTICATED")
            print(f"  Expires: {expires_at[:19]} ({days:.1f} days remaining)")
        else:
            print(f"  Status: EXPIRED ({abs(days):.1f} days ago)")
            print(f"  Run: python scripts/robinhood_login.py")
    elif not expires_at:
        print("  Status: AUTHENTICATED (no expiry data)")

    session = requests.Session()
    session.headers.update(robinhood_headers)
    session.headers["Authorization"] = f"Bearer {cached['access_token']}"
    try:
        res = session.get("https://api.robinhood.com/user/", timeout=10)
        if res.status_code == 200:
            print(f"  API: REACHABLE")
        else:
            print(f"  API: UNREACHABLE (status {res.status_code})")
            print(f"  Token may need refresh. Run: python scripts/robinhood_login.py")
    except requests.RequestException as e:
        print(f"  API: CONNECTION ERROR ({e})")


def revoke() -> bool:
    """Revoke all stored tokens. Returns True iff server-side revocation confirmed."""
    print("\n  Revoking Tokens")
    print("  " + "=" * 40)

    try:
        ok = revoke_session()
    except Exception as exc:
        print(f"  Revocation error: {exc}", file=sys.stderr)
        print()
        return False

    if ok:
        print("  All tokens revoked and credentials file deleted.")
    else:
        print("  WARNING: server-side revocation failed — token may still be live.", file=sys.stderr)
        print("  Local file retained. Retry, or revoke at robinhood.com.")

    print()
    return ok


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
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    parser = argparse.ArgumentParser(
        description="Robinhood Authentication CLI",
        epilog="Opens robinhood.com/login in a browser. Tokens captured automatically.",
    )
    parser.add_argument("--status", action="store_true", help="Check token health")
    parser.add_argument("--revoke", action="store_true", help="Revoke all tokens (emergency)")
    parser.add_argument("--where", action="store_true", help="Print credentials file path")
    parser.add_argument(
        "--refresh", action="store_true",
        help="Headless token refresh via saved browser profile (no user interaction). "
             "Falls back to interactive login if profile is missing or session expired.",
    )
    args = parser.parse_args()

    if args.status:
        check_status()
    elif args.revoke:
        sys.exit(0 if revoke() else 1)
    elif args.where:
        where()
    elif args.refresh:
        ok = refresh_headless()
        if not ok:
            logger.info("Headless refresh failed — falling back to interactive login.")
            ok = login()
        sys.exit(0 if ok else 1)
    else:
        sys.exit(0 if login() else 1)


if __name__ == "__main__":
    main()
