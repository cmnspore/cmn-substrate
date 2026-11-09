#!/usr/bin/env python3
"""Check the conformance package using only the Python standard library."""

import json
from pathlib import Path
import sys


VERSION = "cmn-conformance-v1"


def check_manifest(root: Path) -> None:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != VERSION:
        raise ValueError("manifest version must be " + VERSION)
    vectors = manifest.get("vectors")
    if not isinstance(vectors, dict) or not vectors:
        raise ValueError("manifest vectors must be a nonempty object")
    listed = list(vectors.values())
    if any(not isinstance(path, str) for path in listed):
        raise ValueError("vector paths must be strings")
    if len(set(listed)) != len(listed):
        raise ValueError("duplicate vector path in manifest")
    for path in listed:
        parts = Path(path).parts
        if len(parts) != 2 or parts[0] != "vectors" or not parts[1].endswith(".json"):
            raise ValueError("invalid vector path: " + path)
    actual = {path.relative_to(root).as_posix() for path in (root / "vectors").rglob("*.json")}
    if set(listed) != actual:
        raise ValueError(
            f"vector file mismatch: missing={sorted(set(listed) - actual)}, "
            f"unlisted={sorted(actual - set(listed))}"
        )
    for path in listed:
        document = json.loads((root / path).read_text(encoding="utf-8"))
        if document.get("version") != VERSION:
            raise ValueError(path + ": invalid version")
        cases = document.get("cases")
        if not isinstance(cases, list) or not cases:
            raise ValueError(path + ": cases must be a nonempty array")
        ids = [case.get("id") if isinstance(case, dict) else None for case in cases]
        if any(not isinstance(case_id, str) or not case_id for case_id in ids):
            raise ValueError(path + ": case id must be a nonempty string")
        if len(set(ids)) != len(ids):
            raise ValueError(path + ": duplicate case id")


if __name__ == "__main__":
    try:
        check_manifest(Path(__file__).resolve().parent)
    except (OSError, ValueError, TypeError, AttributeError) as error:
        print("Conformance check failed: " + str(error), file=sys.stderr)
        sys.exit(1)
    print("Conformance manifest is consistent")
