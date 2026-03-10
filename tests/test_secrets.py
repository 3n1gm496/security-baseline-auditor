"""Unit tests for auditor.checks.secrets."""

import os
import tempfile
import pytest

from auditor.checks.secrets import scan_secrets, _scan_file, _should_scan, _matches_denylist
from auditor.utils.platform import mask_secret


class TestMaskSecret:
    def test_mask_long(self):
        result = mask_secret("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert "****" in result

    def test_mask_short(self):
        result = mask_secret("abc")
        assert result == "***"

    def test_mask_exact(self):
        result = mask_secret("abcd", visible_chars=4)
        assert result == "****"


class TestShouldScan:
    def test_env_file(self):
        assert _should_scan(".env") is True

    def test_python_file(self):
        assert _should_scan("config.py") is True

    def test_binary_file(self):
        assert _should_scan("image.png") is False

    def test_yaml_file(self):
        assert _should_scan("docker-compose.yml") is True


class TestMatchesDenylist:
    def test_git_dir(self):
        assert _matches_denylist("/home/user/project/.git/config",
                                 ["*/.git/*"]) is True

    def test_normal_path(self):
        assert _matches_denylist("/home/user/project/src/main.py",
                                 ["*/.git/*"]) is False


class TestScanFile:
    def test_detect_aws_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                         delete=False) as f:
            f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
            f.flush()
            findings = _scan_file(f.name)
        os.unlink(f.name)
        assert len(findings) >= 1
        assert any("AWS" in s.pattern_name for s in findings)

    def test_detect_github_token(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".env",
                                         delete=False) as f:
            f.write('GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n')
            f.flush()
            findings = _scan_file(f.name)
        os.unlink(f.name)
        assert len(findings) >= 1
        assert any("GitHub" in s.pattern_name for s in findings)

    def test_detect_private_key(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem",
                                         delete=False) as f:
            f.write('-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n')
            f.flush()
            findings = _scan_file(f.name)
        os.unlink(f.name)
        assert len(findings) >= 1
        assert any("Private Key" in s.pattern_name for s in findings)

    def test_no_false_positive_on_clean(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py",
                                         delete=False) as f:
            f.write('x = 42\nprint("hello world")\n')
            f.flush()
            findings = _scan_file(f.name)
        os.unlink(f.name)
        assert len(findings) == 0


class TestScanSecrets:
    def test_scan_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file with a secret
            secret_file = os.path.join(tmpdir, "config.py")
            with open(secret_file, "w") as f:
                f.write('api_key = "AKIAIOSFODNN7EXAMPLE"\n')

            findings = scan_secrets([tmpdir])
            assert len(findings) >= 1

    def test_scan_with_exclude(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            secret_file = os.path.join(tmpdir, "config.py")
            with open(secret_file, "w") as f:
                f.write('api_key = "AKIAIOSFODNN7EXAMPLE"\n')

            findings = scan_secrets([tmpdir], exclude=[f"{tmpdir}/*"])
            assert len(findings) == 0

    def test_scan_empty_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = scan_secrets([tmpdir])
            assert len(findings) == 0
