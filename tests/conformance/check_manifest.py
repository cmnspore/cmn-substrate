#!/usr/bin/env python3
"""Validate that the conformance manifest fully covers the vector directory."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parent
    manifest_path = root / "manifest.json"
    vectors_dir = root / "vectors"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_version = manifest.get("version")
    manifest_vectors = manifest.get("vectors", {})

    errors: list[str] = []

    if not manifest_version:
        errors.append("manifest.json is missing top-level 'version'")

    if not isinstance(manifest_vectors, dict) or not manifest_vectors:
        errors.append("manifest.json is missing non-empty 'vectors' map")
        manifest_vectors = {}

    actual_files = sorted(path.relative_to(root).as_posix() for path in vectors_dir.glob("*.json"))
    manifest_files = sorted(manifest_vectors.values())

    missing_from_manifest = sorted(set(actual_files) - set(manifest_files))
    missing_on_disk = sorted(set(manifest_files) - set(actual_files))

    for rel_path in missing_from_manifest:
        errors.append(f"vector file not listed in manifest: {rel_path}")

    for rel_path in missing_on_disk:
        errors.append(f"manifest entry points to missing file: {rel_path}")

    seen_targets: set[str] = set()
    for name, rel_path in sorted(manifest_vectors.items()):
        if rel_path in seen_targets:
            errors.append(f"duplicate manifest target: {rel_path}")
        seen_targets.add(rel_path)

        expected_name = Path(rel_path).stem
        if name != expected_name:
            errors.append(
                f"manifest key '{name}' does not match file stem '{expected_name}' for {rel_path}"
            )

        path = root / rel_path
        if not path.exists():
            continue

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"{rel_path} is not valid JSON: {exc}")
            continue

        version = data.get("version")
        if version != manifest_version:
            errors.append(
                f"{rel_path} version mismatch: expected {manifest_version!r}, found {version!r}"
            )

        cases = data.get("cases")
        if not isinstance(cases, list) or not cases:
            errors.append(f"{rel_path} must contain a non-empty 'cases' array")

    if errors:
        print("Conformance manifest check failed:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print(
        f"Conformance manifest OK: {len(manifest_vectors)} vector files registered and version-aligned."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
