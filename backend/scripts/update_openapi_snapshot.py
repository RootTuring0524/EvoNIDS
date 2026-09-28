"""Regenerate the OpenAPI contract snapshot committed at
``tests/fixtures/openapi.json``.

CI regenerates the snapshot and fails on any ``git diff`` so every API change
must be accompanied by its contract update (run this script, review the diff,
and commit both together).
"""
from __future__ import annotations

import json
from pathlib import Path

from app.main import app

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "openapi.json"


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    snapshot = json.dumps(app.openapi(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    OUT.write_text(snapshot, encoding="utf-8")
    print(f"openapi snapshot written: {OUT} ({len(snapshot)} bytes)")


if __name__ == "__main__":
    main()
