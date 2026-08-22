#!/usr/bin/env python3
"""Strict policy and loader for the canonical VIP dependency manifest."""

from __future__ import annotations

import json
from pathlib import Path
import re


ALLOWED_RELATIONSHIPS = frozenset({
    "BUILD_TOOL_OF",
    "BUILD_DEPENDENCY_OF",
    "RUNTIME_DEPENDENCY_OF",
    "PROVIDED_DEPENDENCY_OF",
    "OPTIONAL_DEPENDENCY_OF",
})

# This policy is deliberately independent from dependency-manifest.json. A
# modified manifest therefore cannot legitimize an unknown or reclassified
# dependency merely by changing its own declarations.
EXPECTED_POLICY: dict[str, tuple[frozenset[str], bool]] = {
    "build-environment": (frozenset({"BUILD_TOOL_OF"}), True),
    "ambuild": (frozenset({"BUILD_TOOL_OF"}), True),
    "metamod-source": (frozenset({"BUILD_DEPENDENCY_OF", "PROVIDED_DEPENDENCY_OF"}), True),
    "hl2sdk-cs2": (frozenset({"BUILD_DEPENDENCY_OF"}), True),
    "hl2sdk-manifests": (frozenset({"BUILD_TOOL_OF"}), True),
    "schemaentity": (frozenset({"BUILD_DEPENDENCY_OF"}), True),
    "protoc": (frozenset({"BUILD_TOOL_OF"}), True),
    "python-pip": (frozenset({"BUILD_TOOL_OF"}), True),
    "python-setuptools": (frozenset({"BUILD_TOOL_OF"}), True),
    "python-importlib-metadata": (frozenset({"BUILD_TOOL_OF"}), True),
    "python-zipp": (frozenset({"BUILD_TOOL_OF"}), True),
    "cs2-runtime": (frozenset({"RUNTIME_DEPENDENCY_OF"}), True),
    "utils-provider": (frozenset({"PROVIDED_DEPENDENCY_OF"}), True),
    "menus-provider": (frozenset({"PROVIDED_DEPENDENCY_OF"}), True),
    "players-provider": (frozenset({"PROVIDED_DEPENDENCY_OF"}), True),
    "sqlmm-provider": (frozenset({"RUNTIME_DEPENDENCY_OF"}), True),
    "cookies-provider": (frozenset({"OPTIONAL_DEPENDENCY_OF"}), False),
}


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"dependency manifest {field} must be a non-empty string")
    return value.strip()


def load_dependency_manifest(path: Path) -> list[dict]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read dependency manifest: {exc}") from exc
    if not isinstance(document, dict) or document.get("schema_version") != 1:
        raise ValueError("dependency manifest schema_version must be 1")
    unknown_document_fields = set(document) - {"$schema", "schema_version", "dependencies"}
    if unknown_document_fields:
        raise ValueError(
            f"dependency manifest has unknown fields: {sorted(unknown_document_fields)}"
        )
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        raise ValueError("dependency manifest dependencies must be an array")

    normalized: list[dict] = []
    seen_capabilities: set[str] = set()
    seen_names: set[str] = set()
    for index, raw in enumerate(dependencies):
        if not isinstance(raw, dict):
            raise ValueError(f"dependency manifest entry {index} must be an object")
        unknown_fields = set(raw) - {
            "capability", "name", "version", "download_location", "purpose",
            "required", "relationships", "artifact_sha256", "version_evidence",
        }
        if unknown_fields:
            raise ValueError(f"dependency manifest entry {index} has unknown fields: {sorted(unknown_fields)}")
        capability = _text(raw.get("capability"), f"entry {index}.capability")
        name = _text(raw.get("name"), f"entry {index}.name")
        version = _text(raw.get("version"), f"entry {index}.version")
        location = _text(raw.get("download_location"), f"entry {index}.download_location")
        purpose = _text(raw.get("purpose"), f"entry {index}.purpose")
        if capability in seen_capabilities:
            raise ValueError(f"duplicate dependency capability: {capability}")
        if name.casefold() in seen_names:
            raise ValueError(f"duplicate dependency name: {name}")
        seen_capabilities.add(capability)
        seen_names.add(name.casefold())

        relationships = raw.get("relationships")
        if not isinstance(relationships, list) or not relationships or not all(
                isinstance(item, str) for item in relationships):
            raise ValueError(f"dependency {capability} relationships must be a non-empty string array")
        relationship_set = frozenset(relationships)
        if len(relationship_set) != len(relationships):
            raise ValueError(f"dependency {capability} has duplicate relationships")
        if not relationship_set <= ALLOWED_RELATIONSHIPS:
            raise ValueError(f"dependency {capability} has unsupported relationships")
        policy = EXPECTED_POLICY.get(capability)
        if policy is None:
            raise ValueError(f"unknown dependency capability: {capability}")
        required = raw.get("required")
        if not isinstance(required, bool):
            raise ValueError(f"dependency {capability} required must be boolean")
        if relationship_set != policy[0] or required != policy[1]:
            raise ValueError(f"dependency {capability} is misclassified")

        artifact_sha256 = raw.get("artifact_sha256")
        if artifact_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", str(artifact_sha256)):
            raise ValueError(f"dependency {capability} artifact_sha256 must be lowercase SHA-256")
        version_evidence = raw.get("version_evidence")
        if version_evidence is not None:
            version_evidence = _text(version_evidence, f"entry {index}.version_evidence")
            if capability != "cs2-runtime":
                raise ValueError("version_evidence is only permitted for cs2-runtime")

        normalized.append({
            "capability": capability,
            "name": name,
            "version": version,
            "download_location": location,
            "purpose": purpose,
            "required": required,
            "relationships": sorted(relationship_set),
            **({"artifact_sha256": artifact_sha256} if artifact_sha256 else {}),
            **({"version_evidence": version_evidence} if version_evidence else {}),
        })

    missing = set(EXPECTED_POLICY) - seen_capabilities
    if missing:
        raise ValueError(f"dependency manifest is missing capabilities: {sorted(missing)}")
    return sorted(normalized, key=lambda item: item["capability"])
