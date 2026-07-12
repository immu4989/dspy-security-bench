"""Adaptive, defense-aware prompt-injection attacks."""
from dspy_security_bench.attacks.adaptive import (
    STRATEGIES,
    BypassStrategy,
    DefenseAwareAttack,
    best_strategy_for,
    build_adaptive_attack,
    is_adaptive,
)

__all__ = [
    "STRATEGIES",
    "BypassStrategy",
    "DefenseAwareAttack",
    "best_strategy_for",
    "build_adaptive_attack",
    "is_adaptive",
]
