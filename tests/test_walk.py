from pathlib import Path

from polinrider_guard.walk import iter_files


def test_iter_files_prunes_generated_directories(tmp_path: Path) -> None:
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("bad", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "kept.js").write_text("ok", encoding="utf-8")
    assert [path.name for path in iter_files(tmp_path)] == ["kept.js"]
