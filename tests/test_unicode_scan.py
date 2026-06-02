from pathlib import Path

from polinrider_guard.unicode_scan import main, scan_path, scan_text


def test_scan_text_finds_zero_width_space() -> None:
    findings = scan_text("const safe = true;\u200b\n")
    assert len(findings) == 1
    assert findings[0].rule_id == "unicode.invisible_or_private_use"
    assert findings[0].line == 1
    assert findings[0].evidence == "U+200B"


def test_scan_path_ignores_binary_files(tmp_path: Path) -> None:
    (tmp_path / "bad.js").write_text("alert(1)\ufe0f\n", encoding="utf-8")
    (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00" + "\ufe0f".encode())
    findings = scan_path(tmp_path)
    assert [finding.path.name for finding in findings] == ["bad.js"]


def test_unicode_script_json_exit_code(tmp_path: Path, capsys) -> None:
    (tmp_path / "bad.py").write_text("x = 1\ue000\n", encoding="utf-8")
    assert main([str(tmp_path), "--json"]) == 1
    assert "U+E000" in capsys.readouterr().out


def test_scan_text_allows_legitimate_emojis() -> None:
    # Warning sign (U+26A0) + VS16 (U+FE0F)
    assert len(scan_text("⚠️")) == 0
    # ZWJ sequences (Family)
    assert len(scan_text("👨‍👩‍👧‍👦")) == 0
    # Keycap sequence (1 + VS16 + Keycap)
    assert len(scan_text("1️⃣")) == 0
    # Mixed text and emoji
    assert len(scan_text("Warning: ⚠️ Proceed with caution!")) == 0


def test_scan_text_still_flags_suspicious_selectors() -> None:
    # Isolated VS16
    findings = scan_text("\uFE0F")
    assert len(findings) == 1
    assert "variation selector" in findings[0].message

    # VS16 after non-emoji
    findings = scan_text("A\uFE0F")
    assert len(findings) == 1

    # Isolated ZWJ
    findings = scan_text("\u200D")
    assert len(findings) == 1
    assert "zero-width" in findings[0].message

    # Incomplete ZWJ sequence
    findings = scan_text("👨\u200D")
    assert len(findings) == 1
