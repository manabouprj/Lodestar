# Contributing to LODESTAR

Thank you for helping. LODESTAR is licensed under the [Apache License 2.0](LICENSE); by submitting a
contribution you agree that it is licensed under the same terms (Apache-2.0, section 5).

1. Open an issue first for anything larger than a fix, so the design can be agreed.
2. Keep adapters read-only, never commit secrets (`${ENV}` references only) and use fictional data with
   `*.example` domains in tests and samples.
3. Add or update tests; `ruff check lodestar tests` and `pytest -q` must pass.
4. Sign off your commits (`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org/).
5. Open a pull request against `main`; CI (Linux, Windows, container) must be green.

Security issues: see [.github/SECURITY.md](.github/SECURITY.md), not public issues.
