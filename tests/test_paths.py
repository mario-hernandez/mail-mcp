import pytest

from mail_mcp.safety.paths import prepare_download_path, safe_join
from mail_mcp.safety.validation import ValidationError


def test_safe_join_ok(tmp_path):
    out = safe_join(tmp_path, "a", "b.txt")
    assert out == (tmp_path / "a" / "b.txt").resolve()


def test_safe_join_rejects_parent_traversal(tmp_path):
    with pytest.raises(ValidationError):
        safe_join(tmp_path, "..", "etc")


def test_safe_join_rejects_absolute(tmp_path):
    with pytest.raises(ValidationError):
        safe_join(tmp_path, "/etc/passwd")


def test_prepare_download_path_strips_directory(tmp_path):
    target = prepare_download_path(tmp_path, "personal", "../../etc/passwd")
    assert target.parent == (tmp_path / "personal").resolve()
    assert target.name == "passwd"
    assert target.parent.is_dir()


def test_prepare_download_path_rejects_dots(tmp_path):
    with pytest.raises(ValidationError):
        prepare_download_path(tmp_path, "personal", "..")
