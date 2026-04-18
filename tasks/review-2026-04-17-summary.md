# pyrh Coverage Pass — Session Summary (2026-04-17)

Branch: `review/coverage-2026-04-17`
Worktree: `/Users/harishma/Personal/code/pyrh/.worktrees/review-2026-04-17`
Environment: `COVERAGE_FILE=.coverage.review`, `PYTEST_CACHE_DIR=.pytest_cache_review`

This file was last refreshed after the third-pass review findings
(review 4133838911) were applied. All 14 findings were addressed.

## Baseline vs. after

Suite-wide test counts:

- Pre-first-pass baseline: 34 passed + 1 errored + 1 failed.
- After first pass (pre-review): 127 passed + 5 skipped.
- After third-pass review fixes: **154 passed + 5 skipped**.

The 5 skipped tests are pre-existing obsolete `_login_oauth2` assertions
from before the multi-step auth refactor; they are annotated with a
rewrite reason.

Per-file line/branch coverage after the third-pass fixes:

| File | Baseline | After first pass | After third-pass fixes | Notes |
|---|---|---|---|---|
| `pyrh/__init__.py` | 100 % | 100 % | 100 % | — |
| `pyrh/cache.py` | 50 % | 100 % | 100 % | — |
| `pyrh/constants.py` | 100 % | 100 % | 100 % | — |
| `pyrh/exceptions.py` | 100 % | 100 % | 100 % | — |
| `pyrh/models/__init__.py` | 100 % | 100 % | 100 % | — |
| `pyrh/models/base.py` | 75 % | 73 % | 73 % | Out of scope. |
| `pyrh/models/instrument.py` | 85 % | 85 % | 85 % | Out of scope. |
| `pyrh/models/oauth.py` | 69 % | **100 %** | **100 %** | Line + branch. |
| `pyrh/models/portfolio.py` | 100 % | 100 % | 100 % | — |
| `pyrh/models/sessionmanager.py` | **20 %** | 100 % (old) | **99 % line / 99 % branch** | See note below. |
| `pyrh/robinhood.py` | 15 % | 15 % | 15 % | Out of scope. |
| `pyrh/urls.py` | 63 % | **93 %** | **93 %** | — |
| `pyrh/util/*` | 100 % | 100 % | 100 % | — |

Note on `sessionmanager.py`: the post-first-pass "100 %" number was a
35-line-smaller module. The third-pass fixes added ~60 lines of
fail-loud branches (transport classifiers, bearer-rotation guards,
binary-body size marker, APW-malformed raises). Those new branches
push the module to 395 statements with 6 unreachable-in-test lines
(`_log_bearer_fingerprint` empty-Authorization branch, two
defensive `try/except` rails in `_truncate_body`). Final numbers:

- `sessionmanager.py`: **99 % line (395 stmts, 6 missing) / 99 %
  branch (124 branches, 1 partial)**.
- `oauth.py`: **100 % / 100 %** (unchanged).

Both exceed the third-pass review targets (≥ 98 % line / ≥ 95 % branch).

## All commits on this branch (claude_code..HEAD)

First-pass + second-pass commits (pre-review 4133838911):

1. `chore: ignore worktree directories` (pre-existing from setup).
2. `test: unblock baseline by fixing pre-existing test drift`
3. `fix(auth): stop leaking OAuth tokens via INFO logs; isolate session headers`
4. `test: add sessionmanager and urls coverage — 20/63% -> 100/93%`
5. `docs: add 2026-04-17 coverage pass session summary`
6. `fix(sessionmanager): redact OAuth payload in _mfa_oauth2 logs`
7. `test(oauth): widen caplog to DEBUG in token-redaction regression`
8. `test(sessionmanager): regression-pin HEADERS module-dict isolation`
9. `test(sessionmanager): real coverage for _refresh_oauth2 via requests_mock`
10. `test(sessionmanager): add integration-style MFA prompt-flow coverage`
11. `test(sessionmanager): pin network-layer and malformed-response error paths`
12. `style: apply black`
13. `fix(sessionmanager): make _mfa_login_workflow raise on denied approval`
14. `fix(sessionmanager): narrow _poll_prompt_approval catch to RequestException`
15. `fix(sessionmanager): chain __cause__ and embed status at 5 auth raise sites`
16. `fix(sessionmanager): classify refresh failures and stop swallowing errors in login`

Third-pass review (4133838911) fixes:

| # | SHA | Commit | Finding |
|---|---|---|---|
| 17 | `b8cb811` | `chore: revert out-of-scope black reformat from pyrh/robinhood.py (scope cleanup)` | #13 |
| 18 | `29e3069` | `fix(sessionmanager): re-raise InvalidJSONError past the broad RequestException catch in _poll_prompt_approval` | #1 |
| 19 | `c2b03a7` | `fix(sessionmanager): raise on non-200 in _challenge_response instead of log-and-return-False` | #2 |
| 20 | `c8874b6` | `fix(sessionmanager): raise on non-200 in _user_view_post instead of log-and-return-False` | #3 |
| 21 | `86b9ba2` | `fix(sessionmanager): guard 403 body shape and distinguish transport errors from wrong MFA code` | #4 |
| 22 | `2d9d2e6` | `fix(sessionmanager): fail loudly on malformed APW payload instead of silently falling back to input()` | #5 |
| 23 | `46ea794` | `fix(sessionmanager): classify 408/425/429 as transient in _is_permanent_refresh_failure` | #6 |
| 24 | `4c2153a` | `fix(sessionmanager): wrap RequestException in _refresh_oauth2 with synthetic 503 for transient classification` | #7 |
| 25 | `96428cf` | `fix(sessionmanager): refuse to replay stale bearer after 401 auto-refresh in get() / post()` | #8 |
| 26 | `1d18709` | `fix(sessionmanager): increment poll counter on 5xx and tighten reset condition` | #9 |
| 27 | `8b70ab9` | `fix(sessionmanager): gate _truncate_body on Content-Type so binary payloads return a size marker` | #10 |
| 28 | `55ee521` | `test(sessionmanager): tighten vacuous assertions per review findings #11 and #12` | #11, #12 |
| 29 | `c892dfe` | `style: apply black to tests/test_sessionmanager_extra.py` | — |
| 30 | (this) | `docs: refresh review-2026-04-17 summary with third-pass findings` | #14 |

## Fix vs. Acknowledge tally (cumulative)

| Class | Count | Notes |
|---|---|---|
| **Fix** | 18 | 4 first-pass + 14 third-pass. |
| **Acknowledge** | 2 | `urls.chain()` yarl bug (upstream TODO); 5 obsolete `_login_oauth2` tests skipped. |
| **Dismiss** | 0 | — |

## Out of scope this session (deferred)

1. `pyrh/robinhood.py` — 15 % coverage, HTTP-heavy, multi-session job.
2. `pyrh/models/base.py` — 73 %, low-risk gap-fill.
3. `pyrh/models/instrument.py` — 85 %.
4. Rewriting the 5 skipped `_login_oauth2` tests.
5. `pyrh/urls.py::chain()` trailing-slash bug (≤ 2 LOC, needs API validation).
6. Logging hygiene cleanup in `SessionManager.__init__`.

## Follow-up recommendations

- Coverage on `sessionmanager.py` is now at the review target. The
  missed lines are defensive `except AttributeError`/`except TypeError`
  rails inside `_truncate_body` and the empty-Authorization branch of
  `_log_bearer_fingerprint`. They are unreachable with real
  `requests.Response` objects but intentional — leave them uncovered
  rather than writing mock-shape-specific tests that assert behaviour
  of the test double itself.
- `_login_bearer_fingerprint` emits a SHA-256 fingerprint truncated to
  8 hex chars at DEBUG. If a future audit requires zero raw-bearer-ish
  strings in logs, consider rotating to HMAC(device_token, bearer) to
  prevent offline cross-session correlation.
