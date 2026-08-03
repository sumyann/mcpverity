"""Plain-JSON export of a Scan -- the CLI's `--output json` format."""
from typing import Any

from ..models import Scan


def scan_to_json(scan: Scan) -> dict[str, Any]:
    return scan.model_dump(mode="json")
