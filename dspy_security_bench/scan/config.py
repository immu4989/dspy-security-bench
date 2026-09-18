"""Configuration for `dspy-security-bench scan`.

A `ScanConfig` describes what to test (agent, suites, attacks, defenses), how
to decide pass/fail (the gate), and how to report. It loads from a committed
YAML file and/or CLI flags, so a CI job is a one-liner referencing the file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from numbers import Real
from pathlib import Path
from typing import Any


@dataclass
class AgentSpec:
    """How to obtain the agent under test.

    Exactly one of `model` / `import_path` should be set:
      - model: a litellm model string → the built-in function-calling agent.
      - import_path: "module.path:callable" → the callable is imported and
        called with no args; it must return an object satisfying the
        `dspy_security_bench.agents.Agent` protocol.
    """

    model: str | None = None
    import_path: str | None = None
    name: str | None = None  # display name; defaults to model or import_path

    def resolved_name(self) -> str:
        return self.name or self.model or self.import_path or "agent"


@dataclass
class ScanSpec:
    suites: list[str] = field(default_factory=lambda: ["workspace"])
    attacks: list[str] = field(default_factory=lambda: ["direct", "important_instructions"])
    defenses: list[str] = field(default_factory=lambda: ["none"])
    user_tasks: int | str = 5          # int, or "all"
    injection_tasks: int | str = 1


@dataclass
class GateSpec:
    mode: str = "absolute"             # "absolute" | "regression"
    min_security: float = 0.90         # absolute mode
    baseline: str | None = None        # regression mode: path to baseline json
    max_regression: float = 0.10       # regression mode
    warn_margin: float = 0.05          # cells within this of the bar → warning
    require_baseline_coverage: bool = True

    def validate(self) -> None:
        if self.mode not in ("absolute", "regression"):
            raise ValueError("config: gate.mode must be absolute|regression")
        if self.mode == "regression" and not self.baseline:
            raise ValueError("config: gate.mode=regression requires gate.baseline")
        if type(self.require_baseline_coverage) is not bool:
            raise ValueError("config: gate.require_baseline_coverage must be boolean")
        for name in ("min_security", "max_regression", "warn_margin"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, Real) or not 0 <= value <= 1:
                raise ValueError(f"config: gate.{name} must be a finite number between 0 and 1")


@dataclass
class ReportSpec:
    formats: list[str] = field(default_factory=lambda: ["terminal"])
    sarif_out: str = "dsb.sarif"
    json_out: str = "dsb.json"


@dataclass
class ScanConfig:
    agent: AgentSpec = field(default_factory=AgentSpec)
    scan: ScanSpec = field(default_factory=ScanSpec)
    gate: GateSpec = field(default_factory=GateSpec)
    report: ReportSpec = field(default_factory=ReportSpec)
    fail_on: str = "error"             # "error" | "warning" | "never"

    # -- construction ------------------------------------------------------

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanConfig:
        if not isinstance(d, dict):
            raise ValueError("config must be a mapping")
        if set(d) - {"agent", "scan", "gate", "report", "fail_on"}:
            raise ValueError("config contains unknown top-level settings")
        d = d or {}
        agent = d.get("agent") if d.get("agent") is not None else {}
        scan = d.get("scan") if d.get("scan") is not None else {}
        gate = d.get("gate") if d.get("gate") is not None else {}
        report = d.get("report") if d.get("report") is not None else {}
        if any(not isinstance(section, dict) for section in (agent, scan, gate, report)):
            raise ValueError("config sections must be mappings")
        for name, section, allowed in (
            ("agent", agent, {"model", "import", "name"}),
            ("scan", scan, {"suites", "attacks", "defenses", "user_tasks", "injection_tasks"}),
            ("gate", gate, {"mode", "min_security", "baseline", "max_regression", "warn_margin", "require_baseline_coverage"}),
            ("report", report, {"formats", "sarif_out", "json_out"}),
        ):
            if set(section) - allowed:
                raise ValueError(f"config: {name} contains unknown settings")
        return cls(
            agent=AgentSpec(
                model=agent.get("model"),
                import_path=agent.get("import"),
                name=agent.get("name"),
            ),
            scan=ScanSpec(
                suites=scan.get("suites", ScanSpec().suites),
                attacks=scan.get("attacks", ScanSpec().attacks),
                defenses=scan.get("defenses", ScanSpec().defenses),
                user_tasks=scan.get("user_tasks", ScanSpec().user_tasks),
                injection_tasks=scan.get("injection_tasks", ScanSpec().injection_tasks),
            ),
            gate=GateSpec(
                mode=gate.get("mode", GateSpec().mode),
                min_security=gate.get("min_security", GateSpec().min_security),
                baseline=gate.get("baseline"),
                max_regression=gate.get("max_regression", GateSpec().max_regression),
                warn_margin=gate.get("warn_margin", GateSpec().warn_margin),
                require_baseline_coverage=gate.get("require_baseline_coverage", True),
            ),
            report=ReportSpec(
                formats=report.get("formats", ReportSpec().formats),
                sarif_out=report.get("sarif_out", ReportSpec().sarif_out),
                json_out=report.get("json_out", ReportSpec().json_out),
            ),
            fail_on=d.get("fail_on", "error"),
        )

    @classmethod
    def load(cls, path: str | Path) -> ScanConfig:
        import yaml

        class UniqueSafeLoader(yaml.SafeLoader):
            pass

        def mapping(loader, node, deep=False):
            loader.flatten_mapping(node)
            result = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if not isinstance(key, str):
                    raise ValueError("config mapping keys must be strings")
                if key in result:
                    raise ValueError("config contains duplicate YAML keys")
                result[key] = loader.construct_object(value_node, deep=deep)
            return result

        UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
        with Path(path).open("rb") as stream:
            raw = stream.read(1_000_001)
        if len(raw) > 1_000_000:
            raise ValueError("config exceeds 1000000 bytes")
        try:
            payload = yaml.load(raw.decode("utf-8"), Loader=UniqueSafeLoader)
        except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
            raise ValueError("config must be bounded valid UTF-8 YAML") from exc
        return cls.from_dict({} if payload is None else payload)

    def validate(self) -> None:
        """Raise ValueError on an unusable config."""
        if not self.agent.model and not self.agent.import_path:
            raise ValueError("config: set agent.model or agent.import")
        if self.agent.model and self.agent.import_path:
            raise ValueError("config: set only one of agent.model / agent.import")
        for name, value in (("model", self.agent.model), ("import", self.agent.import_path), ("name", self.agent.name)):
            if value is not None and (not isinstance(value, str) or not value or "|" in value):
                raise ValueError(f"config: agent.{name} must be a nonempty string without '|'")
        self.gate.validate()
        if self.fail_on not in ("error", "warning", "never"):
            raise ValueError(f"config: fail_on must be error|warning|never, got {self.fail_on!r}")
        for name in ("suites", "attacks", "defenses"):
            values = getattr(self.scan, name)
            if not isinstance(values, list) or not values or not all(isinstance(value, str) and value and "|" not in value for value in values):
                raise ValueError(f"config: scan.{name} must be a nonempty list of names without '|'")
            if len(set(values)) != len(values):
                raise ValueError(f"config: scan.{name} must not contain duplicates")
        for name, value in (
            ("user_tasks", self.scan.user_tasks),
            ("injection_tasks", self.scan.injection_tasks),
        ):
            if value != "all" and (not isinstance(value, int) or isinstance(value, bool) or value < 1):
                raise ValueError(f"config: scan.{name} must be a positive integer or 'all'")
        if not isinstance(self.report.formats, list) or not self.report.formats or not all(isinstance(fmt, str) for fmt in self.report.formats):
            raise ValueError("config: report.formats must be a nonempty list of names")
        if len(set(self.report.formats)) != len(self.report.formats):
            raise ValueError("config: report.formats must not contain duplicates")
        for name, value in (("json_out", self.report.json_out), ("sarif_out", self.report.sarif_out)):
            if not isinstance(value, str) or not value:
                raise ValueError(f"config: report.{name} must be a nonempty path")
        for fmt in self.report.formats:
            if fmt not in ("terminal", "json", "sarif"):
                raise ValueError(f"config: unknown report format {fmt!r}")
