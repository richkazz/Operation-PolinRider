from pathlib import Path

from polinrider_guard.masquerade import entropy, main, printable_ratio, scan_path


def test_printable_ratio_and_entropy_helpers() -> None:
    assert printable_ratio(b"abc\n") == 1.0
    assert printable_ratio(b"\x00\x01A") < 0.5
    assert entropy(b"aaaa") == 0.0
    assert entropy(b"abcd") > 1.0


def test_scan_path_finds_javascript_hidden_in_font(tmp_path: Path) -> None:
    payload = "function boot(){ eval('1'); } // trongrid.io\n"
    (tmp_path / "theme.woff2").write_text(payload, encoding="utf-8")
    findings = scan_path(tmp_path)
    rule_ids = {finding.rule_id for finding in findings}
    assert "masquerade.binary_extension_contains_script" in rule_ids
    assert "ioc.blockchain_or_known_endpoint_marker" in rule_ids


def test_scan_path_allows_valid_magic_bytes(tmp_path: Path) -> None:
    (tmp_path / "font.woff2").write_bytes(b"wOF2" + b"\x00" * 64)
    assert scan_path(tmp_path) == []


def test_masquerade_script_exit_code(tmp_path: Path, capsys) -> None:
    (tmp_path / "logo.png").write_text("process.exit(eval('0'))", encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    assert "looks like script" in capsys.readouterr().out
