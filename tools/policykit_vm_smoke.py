#!/usr/bin/env python3
"""Exercise the real desktop PolicyKit agent with a read-only image check."""
from __future__ import annotations

import argparse
from pathlib import Path

from transume.client import run_spec
from transume.domain import JobOperation, PublicJobSpec
from transume.draft import image_fingerprint


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repository")
    parser.add_argument("image")
    args = parser.parse_args()
    spec = PublicJobSpec(
        job_id="vm-policykit-check",
        operation=JobOperation.CHECK_IMAGE,
        repository=args.repository,
        image_name=args.image,
        risk="read-only",
        image_fingerprint=image_fingerprint(Path(args.repository) / args.image),
    )
    result = run_spec(spec)
    if result.status != "ok":
        raise RuntimeError(f"PolicyKit-authorized check failed: {result.detail}")
    print(f"PolicyKit authentication and image check passed: {result.detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
