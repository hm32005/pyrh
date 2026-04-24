# coding=utf-8
"""Doc-lockin for issue #143: dead outer-except on pyrh-hierarchy exceptions.

Issue #143 (investment-system-docs): in ``Robinhood.get_popularity`` the
outer ``try/except requests.HTTPError`` block wraps BOTH a call to
``self.quote_data(...)`` and ``self.get_url(popularity_url)``. But
``quote_data`` (after pyrh PR #5 / #79) already dispatches HTTP errors to
pyrh-hierarchy exceptions (``RobinhoodServerError``,
``RobinhoodRateLimitError``, ``InvalidTickerSymbol``) — NONE of which
inherit from ``requests.HTTPError``. So the outer except:

* NEVER catches exceptions from ``quote_data`` — they propagate unchanged
  (which is the correct, desired behavior).
* ONLY catches HTTP errors from the final ``get_url(popularity_url)`` call
  (and from the instrument-URL resolution ``get_url(...)["id"]`` step,
  which is also a raw ``self.get_url``).

A future reader could plausibly misread the outer try/except as "catches
everything" and inadvertently either (a) remove the inner dispatch in
``quote_data``, or (b) widen the outer except to ``Exception``, masking
the pyrh hierarchy. The inline comment we pin here makes the subtlety
explicit so that risk lands in review instead of production.

This test is intentionally a content-lockin: it asserts the comment
phrasing survives code reformatting / minor edits. If the wording is
updated deliberately, update the test in the same commit.
"""
from __future__ import annotations

import inspect

from pyrh.robinhood import Robinhood


def test_get_popularity_has_outer_except_scope_comment():
    """``get_popularity`` must include a comment that explains which
    exceptions flow through the outer ``except requests.HTTPError`` block
    and which do NOT (the pyrh-hierarchy exceptions pre-raised by
    ``quote_data``).

    The phrase we pin is deliberately specific so that a generic
    refactor-rewrite doesn't accidentally delete the explanation.
    """
    source = inspect.getsource(Robinhood.get_popularity)
    # The critical phrase: the comment must mention that pyrh-hierarchy
    # exceptions bypass the outer ``except`` — i.e. they are NOT caught.
    assert "PyrhException" in source or "pyrh hierarchy" in source.lower(), (
        "get_popularity should document that pyrh-hierarchy exceptions "
        "raised by quote_data bypass the outer except requests.HTTPError — "
        "see issue #143."
    )
    # Must mention quote_data as the source of the pre-raised exceptions.
    assert "quote_data" in source, (
        "get_popularity doc comment should name ``quote_data`` as the inner "
        "dispatch site — see issue #143."
    )
    # Must mention ``HTTPError`` so a grep for the outer-except class reaches
    # the explanation.
    assert "HTTPError" in source, (
        "get_popularity doc comment should reference HTTPError so future "
        "readers grepping for the outer-except type find the explanation."
    )
