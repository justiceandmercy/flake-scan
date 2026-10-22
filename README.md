# flake-scan

[![CI](https://github.com/justiceandmercy/flake-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/justiceandmercy/flake-scan/actions/workflows/ci.yml)


> Static analyzer that detects flakiness-risk patterns in test suites, such as unseeded randomness, real sleeps, live network calls, shared mutable state, and order-dependent assertions, with configurable rules and multiple output formats.

[![CI](https://github.com/justiceandmercy/flake-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/justiceandmercy/flake-scan/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Topics:** testing, flaky-tests, static-analysis, cli, python, linting, developer-tools

## Features

- Detects unseeded random and time-based assertions that make tests non-deterministic across runs.
- Flags real sleep and retry loops that hide race conditions instead of awaiting deterministic conditions.
- Identifies live network, filesystem, and database calls that should be mocked or isolated.
- Finds shared mutable module or class state leaked between tests via missing teardown.
- Reports order-dependent tests relying on execution sequence or global fixtures.
- Supports rule enable, disable, and severity overrides through a TOML or YAML config file.
- Outputs findings as human-readable text, JSON, or SARIF for CI integration.
- Provides a baseline file to suppress known findings and track regressions over time.
- Exposes a stable Python API so other tools can embed the scanner and rule engine.
- Ships with a curated catalog of rules documented with examples and suggested fixes.

## Install

git clone https://github.com/justiceandmercy/flake-scan.git
cd flake-scan
pip install .

## Quick start

flake-scan --help

Entry point: `src/main.py`.

## Architecture

- `src/main.py` — CLI entrypoint that parses arguments, loads config, runs the scanner, and renders reports with proper exit codes.
- `src/flakescan/cli.py` — Typer command definitions for scan, list-rules, init-config, and baseline subcommands plus option handling.
- `src/flakescan/config.py` — Discovers and validates configuration from pyproject.toml, .flakescan.toml, and .flakescan.yaml with precedence rules.
- `src/flakescan/models.py` — Dataclasses for Finding, Rule, ScanResult, and Severity plus serialization helpers for reporters.
- `src/flakescan/scanner.py` — Walks the target tree, parses Python files with ast, and dispatches rules while respecting ignores and baselines.
- `src/flakescan/rules.py` — Rule registry, base Rule protocol, and engine that runs enabled rules against an AST and collects findings.
- `src/flakescan/rules_timing.py` — Rules for time.sleep, retry loops, polling, and time-based assertions with suggested deterministic alternatives.
- `src/flakescan/rules_random.py` — Rules for unseeded random, uuid4 in assertions, and non-deterministic iteration over sets and dicts.
- `src/flakescan/rules_io.py` — Rules for live HTTP, socket, subprocess, filesystem, and database calls inside tests.
- `src/flakescan/rules_state.py` — Rules for shared mutable globals, missing teardown, and order-dependent test coupling.
- `src/flakescan/reporters.py` — Text, JSON, and SARIF renderers plus baseline read and write utilities.
- `tests/test_rules.py` — Unit tests covering each rule's positive and negative cases using inline source snippets.
- `tests/test_scanner.py` — Integration tests for file discovery, config precedence, ignores, and baseline suppression.
- `tests/test_cli.py` — End-to-end CLI tests invoking subcommands and checking exit codes and output formats.
- `pyproject.toml` — Project metadata, dependencies, console script entry point, and tool configuration.
- `README.md` — Installation, quick start, configuration reference, and rule catalog overview.
- `docs/rules.md` — Detailed documentation of every rule with examples, rationale, and recommended fixes.

For the full module map and design decisions, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Testing

pytest -q

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). PRs welcome!

## License

MIT — see [LICENSE](LICENSE).
