from __future__ import annotations

import sys

from execution_policy import CommandValidationError, load_execution_policy


def main() -> int:
    try:
        policy = load_execution_policy()
    except CommandValidationError as exc:
        print(f"Policy preflight failed: {exc.message}", file=sys.stderr)
        return 1
    except Exception as exc:  # Defensive fallback for unexpected failures.
        print(f"Policy preflight failed: {exc}", file=sys.stderr)
        return 1

    print(
        "Policy preflight passed: "
        f"{len(policy.allowlist)} allowed command(s), "
        f"{len(policy.deny_binaries)} denied binary name(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
