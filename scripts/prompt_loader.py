#!/usr/bin/env python3
"""Validated loader and provenance helpers for the runtime LLM prompt catalogue."""

from __future__ import annotations

import copy
import hashlib
from pathlib import Path
from typing import Any, Dict, Iterable

try:
    import yaml
except ImportError as exc:  # pragma: no cover - exercised by CI dependency checks
    raise RuntimeError("PyYAML is required to load scripts/llm_prompts.yml") from exc


PROMPTS_PATH = Path(__file__).resolve().parent / "llm_prompts.yml"
_REQUIRED_PROMPT_FIELDS = {
    "version",
    "pipeline_stage",
    "purpose",
    "system_prompt",
    "user_prompt",
}


def load_prompt_catalog(path: Path = PROMPTS_PATH) -> Dict[str, Any]:
    """Load and validate the complete prompt catalogue."""
    raw = path.read_bytes()
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise ValueError(f"Prompt catalogue must be a mapping: {path}")
    for field in ("schema_version", "prompt_set_version", "prompts"):
        if field not in data:
            raise ValueError(f"Prompt catalogue is missing {field!r}: {path}")
    prompts = data["prompts"]
    if not isinstance(prompts, dict) or not prompts:
        raise ValueError(f"Prompt catalogue contains no prompts: {path}")
    for prompt_id, prompt in prompts.items():
        if not isinstance(prompt, dict):
            raise ValueError(f"Prompt {prompt_id!r} must be a mapping")
        missing = sorted(_REQUIRED_PROMPT_FIELDS - set(prompt))
        if missing:
            raise ValueError(f"Prompt {prompt_id!r} is missing: {', '.join(missing)}")
        if not isinstance(prompt["system_prompt"], str) or not prompt["system_prompt"].strip():
            raise ValueError(f"Prompt {prompt_id!r} has an empty system_prompt")
        if not isinstance(prompt["user_prompt"], dict):
            raise ValueError(f"Prompt {prompt_id!r} user_prompt must be a mapping")
    data["sha256"] = hashlib.sha256(raw).hexdigest()
    return data


def load_prompt(prompt_id: str, path: Path = PROMPTS_PATH) -> Dict[str, Any]:
    """Return an isolated prompt definition so callers may inject runtime data."""
    catalog = load_prompt_catalog(path)
    try:
        prompt = catalog["prompts"][prompt_id]
    except KeyError as exc:
        raise KeyError(f"Unknown LLM prompt: {prompt_id}") from exc
    return copy.deepcopy(prompt)


def prompt_provenance(prompt_ids: Iterable[str], path: Path = PROMPTS_PATH) -> Dict[str, Any]:
    """Describe the exact versioned prompts invoked while producing an artifact."""
    catalog = load_prompt_catalog(path)
    used = []
    for prompt_id in prompt_ids:
        try:
            prompt = catalog["prompts"][prompt_id]
        except KeyError as exc:
            raise KeyError(f"Unknown LLM prompt: {prompt_id}") from exc
        used.append({"id": prompt_id, "version": str(prompt["version"])})
    return {
        "schema_version": str(catalog["schema_version"]),
        "prompt_set_version": str(catalog["prompt_set_version"]),
        "prompt_catalog_sha256": catalog["sha256"],
        "prompts": used,
    }
