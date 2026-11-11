# Contributing to WiFiStrike

Thanks for your interest in improving WiFiStrike. This project is a dual-use
security-research and education tool, so contributions carry an extra
responsibility: everything here must help people test **their own** networks
(or networks they are explicitly authorized to test) lawfully and safely.

By participating you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md) and the legal/authorized-use terms in
[SECURITY.md](SECURITY.md).

## Ground Rules

1. **No real-world targets.** Never include real BSSIDs, SSIDs, client MAC
   addresses, geolocations, or capture files from networks you do not own in
   issues, pull requests, commits, tests, or screenshots. Use
   locally-administered placeholder MACs (e.g. `02:00:00:00:00:01`) and
   fictitious SSIDs such as `LAB-TEST-ONLY`.
2. **Offline tests only.** The automated test suite must never open a network
   interface, require root, or transmit/receive over the air. Tests build and
   parse synthetic Scapy packets in memory. PRs that add live-radio behavior to
   the test suite will be rejected.
3. **Don't broaden harm.** Contributions that exist primarily to make misuse
   easier — mass/automated targeting of third parties, evasion of detection for
   unauthorized use, bundling stolen data, etc. — are out of scope and will be
   declined. Improvements to correctness, safety, usability, docs, and
   authorized-testing workflows are welcome.
4. **Stay lawful.** Do not submit code, data, or instructions whose main purpose
   is to break the law or GitHub's Acceptable Use Policies.

## How to Contribute

### Reporting Bugs

Open a [GitHub issue](https://github.com/arxhr007/wifistrike/issues) with:

- What you expected vs. what happened.
- Your OS/distro, Python version, adapter chipset, and driver.
- Exact command used (with any real identifiers redacted).
- Relevant output with real MACs/SSIDs replaced by placeholders.

For **security vulnerabilities in the tool itself**, follow the private
reporting process in [SECURITY.md](SECURITY.md) instead of opening a public
issue.

### Suggesting Features

Open an issue describing the use case and how it serves authorized testing.
Please check existing issues first to avoid duplicates.

### Pull Requests

1. Fork the repo and create a topic branch from `main`.
2. Make focused changes; keep unrelated edits in separate PRs.
3. Add or update offline tests under `tests/` for any behavior change to
   packet construction or parsing.
4. Run the suite locally and make sure it passes:
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   pytest
   ```
5. Update the README / docs if you change flags or behavior.
6. Write a clear PR description explaining **what** and **why**.

## Coding Conventions

- Target Python 3.x; the tool runs on Linux with root and a monitor-mode
  capable adapter.
- Keep the single-file layout (`wifistrike.py`) unless there's a strong reason
  to split it; discuss larger refactors in an issue first.
- Frame-building functions should stay **pure and side-effect-free** (no
  `sendp`/`sniff`), so they remain unit-testable offline — see
  `build_deauth_frame` / `build_deauth_all_frame`.
- Validate user input; fail with a clear message instead of an unhandled
  traceback.
- Match the existing style (standard library + Scapy, simple functions,
  colored output helpers).

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
