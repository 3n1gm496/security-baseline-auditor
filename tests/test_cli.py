"""Unit tests for CLI argument parsing."""

import pytest

from auditor.cli import build_parser, parse_severity
from auditor.models import Severity


class TestBuildParser:
    def test_defaults(self):
        parser = build_parser()
        args = parser.parse_args([])
        assert args.quick is False
        assert args.output_format is None
        assert args.output_dir is None
        assert args.severity_threshold is None
        assert args.verbose is False

    def test_quick_mode(self):
        parser = build_parser()
        args = parser.parse_args(["--quick"])
        assert args.quick is True

    def test_format_json(self):
        parser = build_parser()
        args = parser.parse_args(["--format", "json"])
        assert args.output_format == "json"

    def test_format_html(self):
        parser = build_parser()
        args = parser.parse_args(["--format", "html"])
        assert args.output_format == "html"

    def test_format_md(self):
        parser = build_parser()
        args = parser.parse_args(["--format", "md"])
        assert args.output_format == "md"

    def test_output_dir(self):
        parser = build_parser()
        args = parser.parse_args(["--output", "/tmp/reports"])
        assert args.output_dir == "/tmp/reports"

    def test_paths(self):
        parser = build_parser()
        args = parser.parse_args(["--paths", "/home", "/etc"])
        assert args.paths == ["/home", "/etc"]

    def test_exclude(self):
        parser = build_parser()
        args = parser.parse_args(["--exclude", "*.log", "/tmp"])
        assert args.exclude == ["*.log", "/tmp"]

    def test_severity_threshold(self):
        parser = build_parser()
        args = parser.parse_args(["--severity-threshold", "high"])
        assert args.severity_threshold == Severity.HIGH

    def test_verbose(self):
        parser = build_parser()
        args = parser.parse_args(["-v"])
        assert args.verbose is True


class TestParseSeverity:
    def test_valid(self):
        assert parse_severity("info") == Severity.INFO
        assert parse_severity("HIGH") == Severity.HIGH
        assert parse_severity("Critical") == Severity.CRITICAL

    def test_invalid(self):
        import argparse
        with pytest.raises(argparse.ArgumentTypeError):
            parse_severity("invalid")
