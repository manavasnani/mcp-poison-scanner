"""Reporters: turn a scan's results into text, JSON or SARIF."""

from scanner.report.common import ScanReport
from scanner.report.json_report import render_json
from scanner.report.sarif import render_sarif
from scanner.report.text import render_text

__all__ = ["ScanReport", "render_json", "render_sarif", "render_text"]
