"""Recover an APRSD stats store that cannot be decoded."""

import json
from pathlib import Path


def recover_statsstore(path: str) -> bool:
    """Move an invalid stats store aside and return whether it was recovered."""
    stats_path = Path(path)
    if not stats_path.exists():
        return False

    try:
        with stats_path.open() as stats_file:
            json.load(stats_file)
    except (OSError, json.JSONDecodeError):
        backup_path = stats_path.with_name(f"{stats_path.name}.corrupt")
        suffix = 1
        while backup_path.exists():
            backup_path = stats_path.with_name(
                f"{stats_path.name}.corrupt.{suffix}"
            )
            suffix += 1
        stats_path.rename(backup_path)
        return True

    return False


if __name__ == "__main__":
    import sys

    raise SystemExit(0 if recover_statsstore(sys.argv[1]) else 1)
