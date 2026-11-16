"""CVSS v3 base-score calculator (no third-party dependency)."""

from __future__ import annotations

import math
import re
from typing import Any

VECTOR_RE = re.compile(r"^CVSS:3\.[01]/", re.IGNORECASE)

WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

LABELS: dict[str, dict[str, str]] = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"H": "High", "L": "Low", "N": "None"},
    "I": {"H": "High", "L": "Low", "N": "None"},
    "A": {"H": "High", "L": "Low", "N": "None"},
}

ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def parse_vector(vector: str) -> dict[str, str]:
    vector = vector.strip()
    if not VECTOR_RE.match(vector):
        raise ValueError("Vector must start with CVSS:3.0/ or CVSS:3.1/")
    metrics: dict[str, str] = {}
    for chunk in vector.split("/")[1:]:
        if ":" not in chunk:
            continue
        key, _, value = chunk.partition(":")
        key, value = key.upper(), value.upper()
        if key in ORDER:
            metrics[key] = value
    missing = [key for key in ORDER if key not in metrics]
    if missing:
        raise ValueError(f"Missing metrics: {', '.join(missing)}")
    for key in ORDER:
        if metrics[key] not in LABELS[key]:
            raise ValueError(f"Invalid value `{metrics[key]}` for {key}")
    return metrics


def _roundup(value: float) -> float:
    integer = int(round(value * 100000))
    return math.ceil(integer / 10000) / 10


def base_score(vector: str) -> tuple[float, str, dict[str, str]]:
    metrics = parse_vector(vector)
    scope_changed = metrics["S"] == "C"

    iss = 1 - (
        (1 - WEIGHTS["C"][metrics["C"]])
        * (1 - WEIGHTS["I"][metrics["I"]])
        * (1 - WEIGHTS["A"][metrics["A"]])
    )
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    pr = PR_CHANGED[metrics["PR"]] if scope_changed else WEIGHTS["PR"][metrics["PR"]]
    exploitability = (
        8.22 * WEIGHTS["AV"][metrics["AV"]] * WEIGHTS["AC"][metrics["AC"]] * pr * WEIGHTS["UI"][metrics["UI"]]
    )

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))

    return score, severity(score), metrics


def severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def describe(vector: str) -> list[tuple[str, str, str]]:
    metrics = parse_vector(vector)
    return [(key, metrics[key], LABELS[key][metrics[key]]) for key in ORDER]


def normalise(raw: str) -> str:
    """Accept a vector with or without the CVSS:3.x/ prefix."""
    raw = raw.strip()
    return raw if VECTOR_RE.match(raw) else f"CVSS:3.1/{raw}"


def summarise(vector: str) -> dict[str, Any]:
    score, label, metrics = base_score(normalise(vector))
    return {"score": score, "severity": label, "metrics": metrics}
