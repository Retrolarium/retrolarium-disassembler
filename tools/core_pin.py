"""Validate this checkout's immutable Core pin and expose it to Actions."""

import os
from pathlib import Path
import re


def main():
    try:
        sha = Path(".github/core-ref").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit(f"Cannot read .github/core-ref: {exc}") from exc
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise SystemExit(".github/core-ref must contain one full lowercase commit SHA")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"sha={sha}\n")
    else:
        print(sha)


if __name__ == "__main__":
    main()
