"""Policy loading and validation (schemas/policy.schema.json)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import yaml

_PKG = Path(__file__).resolve().parent


def _resource_dir(name: str) -> Path:
    """Installed wheels carry `_schemas`/`_policies`; a source checkout has them at the repo root."""
    installed = _PKG / f"_{name}"
    return installed if installed.is_dir() else _PKG.parents[1] / name


def schema(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((_resource_dir("schemas") / f"{name}.schema.json").read_text())
    return data


def load(path: Path | None) -> dict[str, Any]:
    """Load and validate a policy; default is the shipped `personal` example profile."""
    p = path or (_resource_dir("policies") / "personal.yaml")
    policy: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
    jsonschema.validate(policy, schema("policy"))
    return policy
