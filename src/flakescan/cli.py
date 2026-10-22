"""Typer command definitions for flake-scan."""

from __future__ import annotations

import ast
import fnmatch
import json
import time
from pathlib import Path
from typing import Any, Iterable, Optional

import typer

from flakescan.config import Config, load_config
from flakescan.models import (
    BUILTIN_RULES,
    Finding,
    ScanResult,
    Severity,
    get_rule,
)

app = typer.Typer(
    name="flake-scan",
    help="Static analyzer for flakiness-risk patterns in test suites.",
    no_args_is_help=True,
)
baseline_app = typer.Typer(help="Create and manage baseline files.")
app.add_typer(baseline_app, name="baseline")

NETWORK_CALLS = {
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.options",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch",
    "httpx.delete", "httpx.head", "httpx.options",
    "urllib.request.urlopen", "socket.create_connection",
}
DATABASE_CALLS = {
    "sqlite3.connect", "psycopg.connect", "psycopg2.connect",
    "mysql.connector.connect", "pymysql.connect", "create_engine",
}
TIME_CALLS = {
    "time.time", "time.monotonic", "time.perf_counter",
    "datetime.now", "datetime.utcnow", "datetime.today",
}
FS_CALLS = {
    "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree",
    "Path.unlink", "Path.write_text", "Path.write_bytes",
}


def _call_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    parts.reverse()
    return ".".join(parts)


def _mutable_expr(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Dict, ast.Set)):
        return True
    if isinstance(node, ast.Call):
        return _call_name(node) in {"list", "dict", "set", "defaultdict"}
    return False


def _contains(node: ast.AST, predicate) -> bool:
    for child in ast.walk(node):
        if predicate(child):
            return True
    return False


def _iter_files(root: Path, config: Config) -> Iterable[Path]:
    for path in sorted(root.rglob("*.py")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) for pattern in config.exclude):
            continue
        if config.include and not any(
            fnmatch.fnmatch(relative, pattern) for pattern in config.include
        ):
            continue
        yield path


def _add_finding(
    findings: list[Finding],
    config: Config,
    rule_id: str,
    path: Path,
    line: int,
    column: int,
    message: str,
) -> None:
    rule = get_rule(rule_id)
    if rule is None or not config.rule_enabled(rule_id, rule.enabled):
        return
    severity = config.rule_severity(rule_id, rule.default_severity)
    findings.append(
        Finding(
            rule_id=rule_id,
            message=message,
            path=str(path),
            line=max(1, line),
            column=max(0, column),
            severity=severity,
        )
    )


def _scan_file(path: Path, root: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return findings

    relative_path = path

    def add(rule_id: str, node: ast.AST, message: str) -> None:
        _add_finding(
            findings,
            config,
            rule_id,
            relative_path,
            getattr(node, "lineno", 1),
            getattr(node, "col_offset", 0),
            message,
        )

    class Visitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.in_class = False

        def visit_Module(self, node: ast.Module) -> None:
            for statement in node.body:
                if isinstance(statement, ast.Assign) and _mutable_expr(statement.value):
                    for target in statement.targets:
                        if isinstance(target, ast.Name):
                            add(
                                "shared-mutable-state",
                                statement,
                                f"Module-level mutable state '{target.id}' can leak between tests.",
                            )
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.in_class = True
            for statement in node.body:
                if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                    value = statement.value if isinstance(statement, ast.Assign) else statement.value
                    if value is not None and _mutable_expr(value):
                        target_name = "attribute"
                        if isinstance(statement, ast.Assign):
                            for target in statement.targets:
                                if isinstance(target, ast.Name):
                                    target_name = target.id
                        elif isinstance(statement.targets if hasattr(statement, "targets") else None, list):
                            pass
                        if isinstance(statement, ast.AnnAssign) and isinstance(
                            statement.target, ast.Name
                        ):
                            target_name = statement.target.id
                        add(
                            "shared-mutable-state",
                            statement,
                            f"Class-level mutable state '{target_name}' can leak between tests.",
                        )
            self.generic_visit(node)
            self.in_class = False

        def visit_Call(self, node: ast.Call) -> None:
            name = _call_name(node)
            if name == "time.sleep" or name.endswith(".sleep"):
                add("real-sleep", node, "Real sleep hides timing-dependent behavior.")
            if name.startswith("random.") and name != "random.seed":
                if "random.seed(" not in source:
                    add(
                        "unseeded-random",
                        node,
                        "Unseeded randomness makes test results non-deterministic.",
                    )
            if name in NETWORK_CALLS or name.startswith(("requests.", "httpx.")):
                add("live-network", node, "Live network call should be mocked or isolated.")
            if name in DATABASE_CALLS or name.endswith(".connect") and any(
                token in name for token in ("sql", "postgres", "mysql", "mongo")
            ):
                add("live-database", node, "Live database call should be isolated or mocked.")
            if name in FS_CALLS:
                add("live-filesystem", node, "Filesystem mutation should be isolated.")
            if name == "open":
                mode = ""
                if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                    mode = str(node.args[1].value)
                for keyword in node.keywords:
                    if keyword.arg == "mode" and isinstance(keyword.value, ast.Constant):
                        mode = str(keyword.value.value)
                if any(flag in mode for flag in ("w", "a", "x", "+")):
                    add("live-filesystem", node, "Filesystem write should be isolated.")
            if name in TIME_CALLS:
                add(
                    "time-based-assertion",
                    node,
                    "Time-based value makes assertions non-deterministic.",
                )
            if name.startswith("os.") and name in {"os.remove", "os.unlink", "os.rmdir"}:
                add("live-filesystem", node, "Filesystem mutation should be isolated.")
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for decorator in node.decorator_list:
                decorator_name = _call_name(decorator)
                if "order" in decorator_name or decorator_name.endswith(".run"):
                    add(
                        "order-dependent-test",
                        decorator,
                        "Test execution order dependency detected.",
                    )
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)  # type: ignore[arg-type]

        def visit_While(self, node: ast.While) -> None:
            if _contains(
                node,
                lambda child: isinstance(child, ast.Call)
                and _call_name(child) in {"time.sleep", "asyncio.sleep"},
            ) or _contains(
                node,
                lambda child: isinstance(child, ast.Name)
                and child.id.lower() in {"retry", "retries", "attempt"},
            ):
                add(
                    "retry-loop",
                    node,
                    "Retry loop can hide race conditions; await a deterministic condition.",
                )
            self.generic_visit(node)

        def visit_For(self, node: ast.For) -> None:
            if _contains(
                node,
                lambda child: isinstance(child, ast.Call)
                and _call_name(child) in {"time.sleep", "asyncio.sleep"},
            ):
                add(
                    "retry-loop",
                    node,
                    "Retry loop can hide race conditions; await a deterministic condition.",
                )
            self.generic_visit(node)

    Visitor().visit(tree)
    return findings


def run_scan(root: Path, config: Config, max_findings: Optional[int] = None) -> ScanResult:
    started = time.monotonic()
    root = Path(root).resolve()
    findings: list[Finding] = []
    files_scanned = 0
    for path in _iter_files(root, config):
        files_scanned += 1
        findings.extend(_scan_file(path, root, config))
        limit = max_findings if max_findings is not None else config.max_findings
        if limit is not None and len(findings) >= limit:
            findings = findings[:limit]
            break
    duration = time.monotonic() - started
    return ScanResult(
        root=root,
        findings=findings,
        files_scanned=files_scanned,
        duration_seconds=round(duration, 6),
        config={
            "include": config.include,
            "exclude": config.exclude,
            "format": config.output_format,
        },
    )


def _load_baseline(path: Path) -> set[str]:
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return set()
    fingerprints: set[str] = set()
    items = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
    for item in items:
        if isinstance(item, str):
            fingerprints.add(item)
        elif isinstance(item, dict):
            fingerprint = item.get("fingerprint")
            if fingerprint:
                fingerprints.add(str(fingerprint))
            else:
                fingerprints.add(f"{item.get('rule_id')}:{item.get('path')}:{item.get('line')}")
    return fingerprints


def _suppress_baseline(result: ScanResult, baseline_path: Optional[Path]) -> ScanResult:
    if baseline_path is None or not Path(baseline_path).exists():
        return result
    fingerprints = _load_baseline(Path(baseline_path))
    kept = [
        finding
        for finding in result.findings
        if finding.fingerprint not in fingerprints
        and f"{finding.rule_id}:{finding.path}:{finding.line}" not in fingerprints
    ]
    return ScanResult(
        root=result.root,
        findings=kept,
        files_scanned=result.files_scanned,
        duration_seconds=result.duration_seconds,
        config=result.config,
    )


def _render_text(result: ScanResult) -> str:
    if not result.findings:
        return f"No findings in {result.files_scanned} scanned files."
    lines = [f"flake-scan: {len(result.findings)} finding(s) in {result.files_scanned} file(s)"]
    for finding in result.findings:
        lines.append(
            f"{finding.path}:{finding.line}:{finding.column} "
            f"[{finding.severity.value}] {finding.rule_id}: {finding.message}"
        )
    return "\n".join(lines)


def _render_sarif(result: ScanResult) -> str:
    rules = []
    seen: set[str] = set()
    for finding in result.findings:
        if finding.rule_id not in seen:
            seen.add(finding.rule_id)
            rule = get_rule(finding.rule_id)
            rules.append(
                {
                    "id": finding.rule_id,
                    "name": rule.title if rule else finding.rule_id,
                    "shortDescription": {"text": rule.description if rule else finding.message},
                }
            )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "flake-scan", "rules": rules}},
                "results": [
                    {
                        "ruleId": finding.rule_id,
                        "level": "error"
                        if finding.severity.rank >= Severity.ERROR.rank
                        else "warning",
                        "message": {"text": finding.message},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": finding.path},
                                    "region": {
                                        "startLine": finding.line,
                                        "startColumn": finding.column + 1,
                                    },
                                }
                            }
                        ],
                    }
                    for finding in result.findings
                ],
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _render(result: ScanResult, output_format: str, output: Optional[Path]) -> None:
    if output_format == "json":
        text = json.dumps(result.to_dict(), indent=2)
    elif output_format == "sarif":
        text = _render_sarif(result)
    else:
        text = _render_text(result)
    if output is not None:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text + "\n", encoding="utf-8")
        typer.echo(f"Wrote report to {output}")
    else:
        typer.echo(text)


@app.command()
def scan(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="Config file path."),
    output_format: Optional[str] = typer.Option(
        None, "--format", "-f", help="Output format: text, json, or sarif."
    ),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Write report to file."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", "-b", help="Baseline file to suppress findings."),
    fail_on: Optional[str] = typer.Option(None, "--fail-on", help="Severity that fails the command."),
    include: Optional[list[str]] = typer.Option(None, "--include", help="Glob(s) to include."),
    exclude: Optional[list[str]] = typer.Option(None, "--exclude", help="Glob(s) to exclude."),
    max_findings: Optional[int] = typer.Option(None, "--max-findings", help="Stop after N findings."),
) -> None:
    """Scan a project for flakiness-risk patterns."""
    try:
        cfg = load_config(path=config, root=path)
    except Exception as exc:
        typer.echo(f"flake-scan: config error: {exc}", err=True)
        raise typer.Exit(2)
    if include:
        cfg.include = include
    if exclude:
        cfg.exclude = exclude
    fmt = output_format or cfg.output_format
    if fmt not in {"text", "json", "sarif"}:
        typer.echo(f"flake-scan: unknown output format: {fmt}", err=True)
        raise typer.Exit(2)
    try:
        result = run_scan(path, cfg, max_findings=max_findings)
    except Exception as exc:
        typer.echo(f"flake-scan: scan failed: {exc}", err=True)
        raise typer.Exit(2)
    baseline_path = baseline if baseline is not None else cfg.baseline
    result = _suppress_baseline(result, baseline_path)
    _render(result, fmt, output)
    threshold = Severity.normalize(fail_on if fail_on is not None else cfg.fail_on)
    if any(finding.severity.rank >= threshold.rank for finding in result.findings):
        raise typer.Exit(1)


@app.command("list-rules")
def list_rules(
    output_format: str = typer.Option("text", "--format", "-f", help="text or json."),
) -> None:
    """List the built-in rule catalog."""
    if output_format == "json":
        typer.echo(json.dumps([rule.to_dict() for rule in BUILTIN_RULES], indent=2))
        return
    for rule in BUILTIN_RULES:
        typer.echo(f"{rule.id} ({rule.default_severity.value}): {rule.title}")
        typer.echo(f"  {rule.description}")
        if rule.fix:
            typer.echo(f"  fix: {rule.fix}")


@app.command("init-config")
def init_config(
    path: Path = typer.Option(Path(".flakescan.toml"), "--path", "-p", help="Config file to create."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Create a starter configuration file."""
    if path.exists() and not force:
        typer.echo(f"flake-scan: refusing to overwrite {path}", err=True)
        raise typer.Exit(2)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        """# flake-scan configuration
include = ["**/*.py"]
exclude = [".git/**", "build/**", "dist/**", "**/.venv/**"]
format = "text"
fail_on = "warning"

[rules]
# unseeded-random = { enabled = true, severity = "warning" }
# real-sleep = { enabled = true, severity = "error" }
""",
        encoding="utf-8",
    )
    typer.echo(f"Wrote {path}")


@baseline_app.command("create")
def baseline_create(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    output: Path = typer.Option(Path(".flakescan-baseline.json"), "--output", "-o"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Create a baseline from current findings."""
    cfg = load_config(path=config, root=path)
    result = run_scan(path, cfg)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"version": 1, "findings": [f.to_dict() for f in result.findings]}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    typer.echo(f"Wrote {len(result.findings)} baseline finding(s) to {output}")


@baseline_app.command("update")
def baseline_update(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    output: Path = typer.Option(Path(".flakescan-baseline.json"), "--output", "-o"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Alias for baseline create."""
    baseline_create(path=path, output=output, config=config)


@baseline_app.command("check")
def baseline_check(
    path: Path = typer.Argument(Path("."), exists=True, file_okay=False, dir_okay=True),
    baseline: Path = typer.Option(Path(".flakescan-baseline.json"), "--baseline", "-b"),
    config: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Fail when findings are not present in the baseline."""
    cfg = load_config(path=config, root=path)
    result = run_scan(path, cfg)
    result = _suppress_baseline(result, baseline)
    if result.findings:
        typer.echo(_render_text(result), err=True)
        raise typer.Exit(1)
    typer.echo("No new findings relative to baseline.")
