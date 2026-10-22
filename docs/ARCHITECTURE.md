# Architecture

flake-scan — Static analyzer that detects flakiness-risk patterns in test suites, such as unseeded randomness, real sleeps, live network calls, shared mutable state, and order-dependent assertions, with configurable rules and multiple output formats.

## Overview

The codebase is organized around a small set of focused modules. Each module owns a
single responsibility and the public surface is kept deliberately small so the tool
stays easy to hack on.

## Module map

| Path | Responsibility |
| ---- | -------------- |
| `src/main.py` | CLI entrypoint that parses arguments, loads config, runs the scanner, and renders reports with proper exit codes. |
| `src/flakescan/cli.py` | Typer command definitions for scan, list-rules, init-config, and baseline subcommands plus option handling. |
| `src/flakescan/config.py` | Discovers and validates configuration from pyproject.toml, .flakescan.toml, and .flakescan.yaml with precedence rules. |
| `src/flakescan/models.py` | Dataclasses for Finding, Rule, ScanResult, and Severity plus serialization helpers for reporters. |
| `src/flakescan/scanner.py` | Walks the target tree, parses Python files with ast, and dispatches rules while respecting ignores and baselines. |
| `src/flakescan/rules.py` | Rule registry, base Rule protocol, and engine that runs enabled rules against an AST and collects findings. |
| `src/flakescan/rules_timing.py` | Rules for time.sleep, retry loops, polling, and time-based assertions with suggested deterministic alternatives. |
| `src/flakescan/rules_random.py` | Rules for unseeded random, uuid4 in assertions, and non-deterministic iteration over sets and dicts. |
| `src/flakescan/rules_io.py` | Rules for live HTTP, socket, subprocess, filesystem, and database calls inside tests. |
| `src/flakescan/rules_state.py` | Rules for shared mutable globals, missing teardown, and order-dependent test coupling. |
| `src/flakescan/reporters.py` | Text, JSON, and SARIF renderers plus baseline read and write utilities. |
| `tests/test_rules.py` | Unit tests covering each rule's positive and negative cases using inline source snippets. |
| `tests/test_scanner.py` | Integration tests for file discovery, config precedence, ignores, and baseline suppression. |
| `tests/test_cli.py` | End-to-end CLI tests invoking subcommands and checking exit codes and output formats. |
| `pyproject.toml` | Project metadata, dependencies, console script entry point, and tool configuration. |
| `README.md` | Installation, quick start, configuration reference, and rule catalog overview. |
| `docs/rules.md` | Detailed documentation of every rule with examples, rationale, and recommended fixes. |

## Key design decisions

- **Zero/low runtime dependencies**: the core works from the standard library so
  installs stay fast and supply-chain risk stays low.
- **Configuration before convention**: behavior is tunable through config files and
  documented CLI flags instead of magic environment variables.
- **Structured output modes**: human-readable text by default, machine-readable JSON
  for automation, and DOT/Mermaid exports where a graph applies.
- **Everything is guarded by tests**: the CI matrix runs the suite on every push.

## Data flow

`CLI entrypoint -> config loading -> per-item scanning/processing -> aggregation ->
reporting (text | JSON | graph)`.

## Testing

Unit tests exercise each rule against minimal inline Python snippets asserting finding presence and absence, integration tests run the scanner over fixture directories with config and baseline files, and CLI tests invoke the entrypoint to verify subcommand behavior, exit codes, and all three output formats.

Run them locally with `pytest -q`. CI (`.github/workflows/ci.yml`) executes the
same suite on a version matrix for every push and pull request.
