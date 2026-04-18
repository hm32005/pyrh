# Deferred: `pyrh/robinhood.py` Coverage

**Status**: deferred to its own session
**Scope**: the 1517-LOC `pyrh/robinhood.py` module plus its test file (currently missing)
**Current coverage**: 15 % line (as of 2026-04-18)
**Target**: ≥ 70 % line on the post-refactor auth-adjacent methods; ≥ 50 % on the data-only methods (`get_quote`, `get_historical_quotes`, etc.).

## Why deferred

- Single file holds ~30 public methods with mixed responsibilities: auth plumbing, market data, orders, positions, account, portfolio.
- Comprehensive mocking requires a shared `requests_mock` harness mounted on `sm.session`, plus payload fixtures matching Robinhood's undocumented response shapes.
- Effort estimate: 4–8 hours of focused work; does not fit alongside the per-module reviews done in the 2026-04-17 pass.

## Proposed approach for the follow-up session

1. Slice the file into 3–4 regions by responsibility (auth, market-data, orders, positions/portfolio).
2. For each slice, add `requests_mock` adapters per Robinhood endpoint with realistic JSON payloads (capture 1-2 live responses in a sandbox account and sanitise).
3. Write per-method tests that assert: URL built correctly, payload serialisation, status-code branching, error mapping.
4. Accept that some methods (e.g. `get_dividends`, `get_ach_transfers`) may stay untested if they require live account data — flag with `xfail(reason='requires live account fixture')`.

## Pre-requisites

- Access to a Robinhood sandbox account OR captured anonymised response fixtures.
- The auth-side test harness from `tests/test_sessionmanager_extra.py` is reusable for the `SessionManager` plumbing.

## Prior-round context

- The 2026-04-17 coverage pass on `pyrh/` landed auth hardening in `pyrh/models/{oauth,sessionmanager}.py` (PR #2 on GitHub), bringing those two modules to 99–100 % line + branch. `pyrh/robinhood.py` was intentionally skipped in that pass; see `tasks/review-2026-04-17-summary.md` for the full rationale.

## Checklist for the follow-up session

- [ ] Open a fresh branch `coverage/robinhood-py-2026-mm-dd`.
- [ ] Create `tests/test_robinhood_auth_plumbing.py`, `tests/test_robinhood_market_data.py`, `tests/test_robinhood_orders.py`, `tests/test_robinhood_positions.py`.
- [ ] Build `tests/fixtures/robinhood_responses/` with sanitised JSON fixtures.
- [ ] Land tests in one commit per slice; push.
- [ ] Open a GitHub PR, link it back to the issue opened by this task.
- [ ] Update this doc's Status to "done" once merged.
