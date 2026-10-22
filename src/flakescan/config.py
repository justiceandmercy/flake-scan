"""Configuration discovery and validation for flake-scan."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from flakescan.models import BUILTIN_RULES, Severity


class ConfigError(ValueError):
    """Raised when configuration cannot be loaded or validated."""


@dataclass
class RuleOverride:
    """Per-rule configuration override."""

    enabled: bool | None = None
    severity: Severity | None = None

    def get(self, key: str, default: Any = None) -> Any:
        if key == "enabled":
            return self.enabled if self.enabled is not None else default
        if key == "severity":
            return self.severity if self.severity is not None else default
        return default


@dataclass
class Config:
    """Resolved flake-scan configuration."""

    root: Path = field(default_factory=lambda: Path("."))
    config_path: Path | None = None
    include: list[str] = field(default_factory=lambda: ["**/*.py"])
    exclude: list[str] = field(
        default_factory=lambda: [".git/**", "build/**", "dist/**", "**/.venv/**"]
    )
    rules: dict[str, RuleOverride] = field(default_factory=dict)
    output_format: str = "text"
    fail_on: Severity = Severity.WARNING
    baseline: Path | None = None
    max_findings: int | None = None

    def rule_enabled(self, rule_id: str, default: bool = True) -> bool:
        override = self.rules.get(rule_id)
        if override is not None and override.enabled is not None:
            return override.enabled
        return default

    def rule_severity(self, rule_id: str, default: Severity) -> Severity:
        override = self.rules.get(rule_id)
        if override is not None and override.severity is not None:
            return override.severity
        return default


RULE_IDS = {rule.id for rule in BUILTIN_RULES}
_KNOWN_TOP_LEVEL = {
    "include",
    "exclude",
    "rules",
    "format",
    "output_format",
    "fail_on",
    "fail-on",
    "baseline",
    "max_findings",
    "max-findings",
}
_KNOWN_RULE_KEYS = {"enabled", "severity"}
_VALID_FORMATS = {"text", "json", "sarif"}


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError(
            "PyYAML is required to read YAML configuration files."
        ) from exc
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"Configuration in {path} must be a mapping.")
    return data


def _read_config(path: Path) -> dict[str, Any]:
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        return _read_yaml(path)
    if suffix == ".toml" or path.name == "pyproject.toml":
        return _read_toml(path)
    raise ConfigError(f"Unsupported configuration file type: {path}")


def _normalize_severity(value: Any) -> Severity:
    try:
        return Severity.normalize(value) if hasattr(Severity, "normalize") else Severity(value)
    except Exception as exc:
        raise ConfigError(f"Invalid severity value: {value!r}") from exc


def _build_config(raw: Any, root: Path, path: Path) -> Config:
    if not isinstance(raw, Mapping):
        raise ConfigError("Configuration root must be a mapping.")
    unknown = set(raw) - _KNOWN_TOP_LEVEL
    if unknown:
        raise ConfigError(f"Unknown configuration keys: {sorted(unknown)}")

    include = raw.get("include", ["**/*.py"])
    if not isinstance(include, list) or not all(isinstance(item, str) for item in include):
        raise ConfigError("'include' must be a list of strings.")

    exclude = raw.get("exclude", [".git/**", "build/**", "dist/**", "**/.venv/**"])
    if not isinstance(exclude, list) or not all(isinstance(item, str) for item in exclude):
        raise ConfigError("'exclude' must be a list of strings.")

    rules_raw = raw.get("rules", {})
    if not isinstance(rules_raw, Mapping):
        raise ConfigError("'rules' must be a mapping.")
    rules: dict[str, RuleOverride] = {}
    for rule_id, override in rules_raw.items():
        if rule_id not in RULE_IDS:
            raise ConfigError(f"Unknown rule id: {rule_id}")
        if not isinstance(override, Mapping):
            raise ConfigError(f"Rule override for {rule_id} must be a mapping.")
        unknown_rule_keys = set(override) - _KNOWN_RULE_KEYS
        if unknown_rule_keys:
            raise ConfigError(
                f"Unknown keys for rule {rule_id}: {sorted(unknown_rule_keys)}"
            )
        enabled = override.get("enabled")
        if enabled is not None and not isinstance(enabled, bool):
            raise ConfigError(f"'enabled' for {rule_id} must be a boolean.")
        severity = None
        if "severity" in override and override.get("severity") is not None:
            severity = _normalize_severity(override.get("severity"))
        rules[str(rule_id)] = RuleOverride(enabled=enabled, severity=severity)

    output_format = raw.get("format", raw.get("output_format", "text"))
    if output_format not in _VALID_FORMATS:
        raise ConfigError(f"Unsupported output format: {output_format}")

    fail_on_raw = raw.get("fail_on", raw.get("fail-on", "warning"))
    fail_on = _normalize_severity(fail_on_raw)

    baseline_raw = raw.get("baseline")
    baseline = None
    if baseline_raw is not None:
        if not isinstance(baseline_raw, str):
            raise ConfigError("'baseline' must be a string path.")
        baseline_path = Path(baseline_raw)
        if not baseline_path.is_absolute():
            baseline_path = path.parent / baseline_path
        baseline = baseline_path

    max_findings = raw.get("max_findings", raw.get("max-findings"))
    if max_findings is not None:
        if not isinstance(max_findings, int) or isinstance(max_findings, bool) or max_findings < 0:
            raise ConfigError("'max_findings' must be a non-negative integer.")

    return Config(
        root=root,
        config_path=path,
        include=list(include),
        exclude=list(exclude),
        rules=rules,
        output_format=output_format,
        fail_on=fail_on,
        baseline=baseline,
        max_findings=max_findings,
    )


def discover_config(start: Path | None = None, explicit: Path | None = None) -> Config:
    """Discover configuration using flake-scan precedence rules."""
    start_path = Path(start or ".").resolve()
    if explicit is not None:
        config_path = Path(explicit).expanduser()
        if not config_path.is_file():
            raise ConfigError(f"Configuration file not found: {config_path}")
        raw = _read_config(config_path)
        if config_path.name == "pyproject.toml":
            section = raw.get("tool", {}).get("flake-scan") if isinstance(raw, Mapping) else None
            if section is None:
                raise ConfigError("No [tool.flake-scan] section found in pyproject.toml.")
            raw = section
        return _build_config(raw, start_path, config_path)

    for directory in (start_path, *start_path.parents):
        for filename in (".flakescan.toml", ".flakescan.yaml", ".flakescan.yml"):
            candidate = directory / filename
            if candidate.is_file():
                return _build_config(_read_config(candidate), start_path, candidate)
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file():
            raw = _read_toml(pyproject)
            section = raw.get("tool", {}).get("flake-scan")
            if isinstance(section, Mapping):
                return _build_config(section, start_path, pyproject)

    return Config(root=start_path)


def load_config(
    path: str | Path | None = None,
    root: str | Path | None = None,
    start: str | Path | None = None,
) -> Config:
    """Load configuration from a path or directory.

    A directory argument is treated as the search root, while a file argument is
    treated as an explicit configuration file.
    """
    if path is not None and Path(path).is_dir():
        return discover_config(start=Path(path), explicit=None)
    search_root = Path(root or start or ".")
    return discover_config(start=search_root, explicit=path)


# Severity needs normalize support used above. Add lazily to avoid circular imports.
if not hasattr(Severity, "normalize"):
    @classmethod
    def _normalize(cls, value: Any) -> "Severity":
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            aliases = {
                "err": "error",
                "warn": "warning",
                "information": "info",
            }
            normalized = aliases.get(value.strip().lower(), value.strip().lower())
            try:
                return cls(normalized)
            except ValueError as exc:
                raise ConfigError(f"Invalid severity value: {value!r}") from exc
        raise ConfigError(f"Invalid severity value: {value!r}")

    Severity.normalize = _normalize
