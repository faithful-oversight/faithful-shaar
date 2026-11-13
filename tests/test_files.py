# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for publishing report files on file systems without hard links."""

from __future__ import annotations

import os
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

import pytest

from faithful_shaar.outputs.files import OutputError, write_files

if TYPE_CHECKING:
    from collections.abc import Callable

FILES = {"a.txt": b"first file\n" * 100, "b.txt": b"second file\n" * 100}


class FlakyHandle:
    """A real file handle that fails at one chosen point."""

    def __init__(self, handle: IO[bytes], fail: str) -> None:
        self.handle = handle
        self.fail = fail

    def __enter__(self) -> FlakyHandle:
        """Enter like the real handle."""
        return self

    def __exit__(self, *_: object) -> None:
        """Close the real handle, then fail if asked to fail on close."""
        self.handle.close()
        if self.fail == "close":
            raise OSError(5, "Input/output error")

    def write(self, data: bytes) -> int:
        if self.fail == "write":
            self.handle.write(data[: len(data) // 2])
            self.handle.flush()
            raise OSError(28, "No space left on device")
        return self.handle.write(data)

    def flush(self) -> None:
        self.handle.flush()

    def fileno(self) -> int:
        return self.handle.fileno()


@pytest.fixture
def no_hard_links(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    """Make hard links unsupported; return a switch that injects one failure in the copy."""
    copying = {"on": False}
    fail = {"at": ""}
    real_fdopen = os.fdopen
    real_read = Path.read_bytes

    def no_links(*_: object) -> None:
        copying["on"] = True
        raise OSError(1, "Operation not permitted")

    def fdopen(fd: int, *args: Any, **kwargs: Any) -> object:
        if copying["on"] and fail["at"] == "fdopen":
            raise OSError(24, "Too many open files")
        handle = real_fdopen(fd, *args, **kwargs)
        return FlakyHandle(handle, fail["at"]) if copying["on"] else handle

    def read_bytes(self: Path) -> bytes:
        if copying["on"] and fail["at"] == "read":
            raise OSError(5, "Input/output error")
        return real_read(self)

    monkeypatch.setattr(os, "link", no_links)
    monkeypatch.setattr(os, "fdopen", fdopen)
    monkeypatch.setattr(Path, "read_bytes", read_bytes)

    def inject(point: str) -> None:
        fail["at"] = point

    return inject


def test_copy_fallback_publishes_complete_private_files(
    tmp_path: Path, no_hard_links: Callable[[str], None]
) -> None:
    no_hard_links("")
    written = write_files(tmp_path, FILES, force=False)
    assert [p.name for p in written] == list(FILES)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(FILES)
    for path in written:
        assert path.read_bytes() == FILES[path.name]
        if os.name == "posix":
            assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("point", ["read", "fdopen", "write", "close"])
def test_copy_fallback_failure_leaves_no_partial_file(
    tmp_path: Path, no_hard_links: Callable[[str], None], point: str
) -> None:
    """A read, partial write, or close failure removes the file the fallback created."""
    no_hard_links(point)
    with pytest.raises(OutputError, match="the directory is unchanged"):
        write_files(tmp_path, FILES, force=False)
    assert list(tmp_path.iterdir()) == []


def test_copy_fallback_never_removes_a_file_it_did_not_create(
    tmp_path: Path, no_hard_links: Callable[[str], None]
) -> None:
    """A name taken by someone else before the exclusive create is left alone."""
    no_hard_links("")
    real_open = os.open

    def racing_open(path: str, flags: int, mode: int = 0o777) -> int:
        if str(path).endswith("b.txt"):
            Path(path).write_text("someone else", encoding="utf-8")
        return real_open(path, flags, mode)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(os, "open", racing_open)
        with pytest.raises(OutputError, match="appeared while writing"):
            write_files(tmp_path, FILES, force=False)
    assert [p.name for p in tmp_path.iterdir()] == ["b.txt"]
    assert (tmp_path / "b.txt").read_text(encoding="utf-8") == "someone else"


# Publishing with hard links, replacing, and refusing ----------------------------------


def test_files_are_written_unchanged_and_private(tmp_path: Path) -> None:
    out = tmp_path / "new" / "deeper"
    written = write_files(out, FILES, force=False)
    assert [p.name for p in written] == list(FILES)
    for path in written:
        assert path.read_bytes() == FILES[path.name]
        if os.name == "posix":
            assert path.stat().st_mode & 0o777 == 0o600
    assert sorted(p.name for p in out.iterdir()) == sorted(FILES)
    if os.name == "posix":
        assert out.stat().st_mode & 0o777 == 0o700


def test_an_existing_file_is_refused_without_force_and_left_alone(tmp_path: Path) -> None:
    (tmp_path / "b.txt").write_bytes(b"mine")
    with pytest.raises(OutputError, match=r"b\.txt already exists; use --force"):
        write_files(tmp_path, FILES, force=False)
    assert (tmp_path / "b.txt").read_bytes() == b"mine"
    assert [p.name for p in tmp_path.iterdir()] == ["b.txt"]


def test_several_existing_files_are_all_named(tmp_path: Path) -> None:
    for name in FILES:
        (tmp_path / name).write_bytes(b"x")
    with pytest.raises(OutputError, match="already exist; use --force"):
        write_files(tmp_path, FILES, force=False)


def test_force_replaces_every_file_and_leaves_no_backup(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    write_files(tmp_path, FILES, force=True)
    assert (tmp_path / "a.txt").read_bytes() == FILES["a.txt"]
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(FILES)
    if os.name == "posix":
        assert (tmp_path / "a.txt").stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name != "posix", reason="symbolic links need POSIX here")
@pytest.mark.parametrize("force", [False, True])
def test_a_symlink_at_a_target_is_never_followed(tmp_path: Path, *, force: bool) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"precious")
    out = tmp_path / "out"
    out.mkdir()
    (out / "a.txt").symlink_to(victim)
    if force:
        write_files(out, FILES, force=True)
        assert not (out / "a.txt").is_symlink()
        assert (out / "a.txt").read_bytes() == FILES["a.txt"]
    else:
        with pytest.raises(OutputError, match="already exists"):
            write_files(out, FILES, force=False)
        assert (out / "a.txt").is_symlink()
    assert victim.read_bytes() == b"precious"


@pytest.mark.skipif(os.name != "posix", reason="symbolic links need POSIX here")
def test_a_dangling_symlink_counts_as_existing(tmp_path: Path) -> None:
    (tmp_path / "a.txt").symlink_to(tmp_path / "nowhere")
    with pytest.raises(OutputError, match="already exists"):
        write_files(tmp_path, FILES, force=False)
    assert not (tmp_path / "nowhere").exists()


def test_a_directory_at_a_target_is_refused_even_with_force(tmp_path: Path) -> None:
    (tmp_path / "a.txt").mkdir()
    with pytest.raises(OutputError, match="is a directory"):
        write_files(tmp_path, FILES, force=True)


def test_an_output_directory_that_cannot_be_made_is_reported(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_bytes(b"x")
    with pytest.raises(OutputError, match="cannot create"):
        write_files(blocker / "sub", FILES, force=False)


def test_a_failure_while_staging_leaves_the_directory_unchanged(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_fsync = os.fsync
    calls = {"n": 0}

    def fsync(fd: int) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError(28, "No space left on device")
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    with pytest.raises(OutputError, match="the directory is unchanged"):
        write_files(tmp_path, FILES, force=False)
    assert list(tmp_path.iterdir()) == []


def test_a_forced_replace_that_fails_restores_the_old_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in FILES:
        (tmp_path / name).write_bytes(b"old " + name.encode())
    real_replace = Path.replace
    calls = {"n": 0}

    def replace(self: Path, target: Path) -> Path:
        calls["n"] += 1
        # two moves to backups, then the first new file in, then the second fails
        if calls["n"] == 4:
            raise OSError(5, "Input/output error")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", replace)
    with pytest.raises(OutputError, match="the directory is unchanged"):
        write_files(tmp_path, FILES, force=True)
    monkeypatch.undo()
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == {
        name: b"old " + name.encode() for name in FILES
    }


def test_a_failed_backup_move_is_undone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "a.txt").write_bytes(b"old")
    real_replace = Path.replace

    def replace(self: Path, target: Path) -> Path:
        if self.name == "a.txt":
            raise OSError(13, "Permission denied")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", replace)
    with pytest.raises(OutputError, match="the directory is unchanged"):
        write_files(tmp_path, FILES, force=True)
    monkeypatch.undo()
    assert [p.name for p in tmp_path.iterdir()] == ["a.txt"]
    assert (tmp_path / "a.txt").read_bytes() == b"old"


def test_a_failure_after_the_first_link_removes_the_placed_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_link = os.link
    calls = {"n": 0}

    def link(src: str | Path, dst: str | Path) -> None:
        calls["n"] += 1
        if calls["n"] == 2:
            raise PermissionError(13, "Permission denied")
        real_link(src, dst)

    monkeypatch.setattr(os, "link", link)
    monkeypatch.setattr(os, "open", lambda *_a, **_k: (_ for _ in ()).throw(OSError(13, "no")))
    with pytest.raises(OutputError, match="the directory is unchanged"):
        write_files(tmp_path, FILES, force=False)
    assert list(tmp_path.iterdir()) == []


def test_a_name_that_appears_during_linking_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_link = os.link

    def link(src: str | Path, dst: str | Path) -> None:
        if str(dst).endswith("b.txt"):
            Path(dst).write_bytes(b"someone else")
        real_link(src, dst)

    monkeypatch.setattr(os, "link", link)
    with pytest.raises(OutputError, match="appeared while writing"):
        write_files(tmp_path, FILES, force=False)
    assert [p.name for p in tmp_path.iterdir()] == ["b.txt"]
