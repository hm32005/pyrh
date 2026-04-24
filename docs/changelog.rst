# coding=utf-8
.. _changelog:

Changelog
#########

.. towncrier release notes start

Pyrh 2.2.0 (unreleased)
=======================

Features
--------

- ``Robinhood.get_option_market_data_batch(instrument_urls, batch_size=40)``:
  batched options market-data fetch. One ``GET /marketdata/options/`` per
  batch instead of one per contract. ~40x fewer HTTP calls for daily
  options scans. Returns pricing + Greeks + IV, preserves input order.
- ``urls.marketdata_options(instrument_urls)``: URL builder for the batched
  options market-data endpoint (sibling of ``urls.market_data_quotes``).

Bugfixes
--------

- ``Robinhood.get_options`` now follows the ``next`` pagination cursor
  until the chain is exhausted. Previously only page 1 of results was
  returned — silent data loss for high-strike-count tickers (AAPL weekly
  expirations routinely exceed a single page). A safety cap of 100 pages
  prevents infinite loops on pathological paginator responses; callers
  still receive whatever was collected.

Pyrh 2.1.2 (2023-03-04)
=======================

Features
--------

- Added on-demand MFA generation to SessionManager (#300)


Misc
----

- #299, #301, #306


Pyrh 2.1.1 (2023-01-21)
=======================

Features
--------

- Automating MFA authentication using `PyOTP` (#303)


Pyrh 2.0.1 (2022-11-25)
=======================

Features
--------

- Add SessionManager to handle oauth and refresh (#215)
- Add marshmallow support for internal models. (#223)
- Added Robinhood watchlists API integration to retrieve watchlist details (stocks) of given authenticated user. (#225)
- Add Instruments model to the project. (#227)


Bugfixes
--------

- Set default challenge method to sms, email no longer works (83c03133b4fc7a8845de2ae1093136973fe988ce)
- Updated the .get_historical_quotes() to use the URL method .with_query() in order to build a URL with params. (#229)
- Fix the options functions. (#235)
- Fix bug in cancel_order due to wrong concatenation syntax. (#296)


Misc
----

- #226


Pyrh 2.0 (2022-11-25)
=====================

Features
--------

- Add SessionManager to handle oauth and refresh (#215)
- Add marshmallow support for internal models. (#223)
- Added Robinhood watchlists API integration to retrieve watchlist details (stocks) of given authenticated user. (#225)
- Add Instruments model to the project. (#227)


Bugfixes
--------

- Set default challenge method to sms, email no longer works (83c03133b4fc7a8845de2ae1093136973fe988ce)
- Updated the .get_historical_quotes() to use the URL method .with_query() in order to build a URL with params. (#229)
- Fix the options functions. (#235)
- Fix bug in cancel_order due to wrong concatenation syntax. (#296)


Misc
----

- #226


pyrh 2.0 (2020-03-18)
=====================
- Fixed 2fa connection issues
- Last version to support python 2

pyrh 1.0.1 (2017-11-07)
=======================
- Added custom exception
