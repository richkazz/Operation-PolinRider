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
