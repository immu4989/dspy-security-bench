"""IncidentTwin: synthetic cyber-response agent mission assurance."""

from dspy_security_bench.incident.benchmark import run_incident_twin
from dspy_security_bench.incident.repeat import run_repeat_incident_twin

__all__ = ["run_incident_twin", "run_repeat_incident_twin"]
