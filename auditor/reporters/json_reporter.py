"""JSON reporter — machine-readable export."""

from __future__ import annotations

import json
import logging
import os

from auditor.models import AuditResult

logger = logging.getLogger(__name__)


class JsonReporter:
    """Export audit results as JSON."""

    def export(self, result: AuditResult, output_dir: str) -> str:
        """Export to JSON file.

        Args:
            result: Audit result.
            output_dir: Output directory.

        Returns:
            Path to the exported file.
        """
        os.makedirs(output_dir, exist_ok=True)
        filename = f"sbaudit-report-{result.timestamp[:19].replace(':', '-')}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)

        logger.info("JSON report exported: %s", filepath)
        return filepath
