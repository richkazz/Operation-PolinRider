import pytest

from polinrider_guard.yara_scanner import HAS_YARA, scan_path


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_yara_scanner_vulnerable_sample(tmp_path):
    vulnerable_file = tmp_path / "test.js"
    vulnerable_file.write_text("const url = 'api.trongrid.io';")

    findings = scan_path(tmp_path)
    assert len(findings) > 0
    assert any("BeaverTail_BlockchainC2" in f.rule_id for f in findings)

@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
def test_yara_scanner_clean_sample(tmp_path):
    clean_file = tmp_path / "clean.js"
    clean_file.write_text("console.log('hello');")

    findings = scan_path(tmp_path)
    yara_findings = [f for f in findings if f.rule_id.startswith("yara.")]
    assert len(yara_findings) == 0
