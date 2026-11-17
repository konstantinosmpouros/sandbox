"""The box is built the same way in both places that build it.

``box/Dockerfile`` (spike, fallback) and the runner's ``box`` stage
(``runner/Dockerfile``, what ships) must install the same document toolchain,
the same Python set and the same helper files, or the gate would prove a box
that is not the one deployed.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _box_stage(text: str) -> str:
    """The runner Dockerfile's ``box`` stage, up to the next ``FROM``."""
    start = text.rfind("\n", 0, text.index(" AS box")) + 1
    return text[start:text.index("\nFROM ", start)]


def _steps(text: str) -> list[str]:
    """The base image and the toolchain / requirements / helper steps, paths normalised."""
    lines = [line.strip().replace("box/", "") for line in text.splitlines()]
    keep = [line for line in lines
            if line.startswith(("FROM python", "RUN sh /tmp/box-toolchain.sh", "RUN pip install"))
            or (line.startswith("COPY") and ("toolchain" in line or "requirements" in line or "probes" in line))]
    return [re.sub(r"\s+AS box$", "", line) for line in keep]


def test_both_dockerfiles_build_the_same_box():
    box = (ROOT / "box" / "Dockerfile").read_text(encoding="utf-8")
    runner = _box_stage((ROOT / "runner" / "Dockerfile").read_text(encoding="utf-8"))
    assert _steps(box) == _steps(runner)
    assert any("toolchain.sh" in step for step in _steps(box))
    assert any("toolchain_check.sh" in step for step in _steps(box))


def test_the_toolchain_installs_what_the_document_skills_call():
    script = (ROOT / "box" / "toolchain.sh").read_text(encoding="utf-8")
    for piece in ("libreoffice-writer-nogui", "libreoffice-calc-nogui", "libreoffice-impress-nogui",
                  "poppler-utils", "pandoc", "qpdf", "zip", "nodejs", "docx@", "pptxgenjs@", "fonts-liberation2",
                  "UserInstallation"):
        assert piece in script, piece
    # npm is a build tool only: the box never runs it.
    assert "apt-get purge -y --auto-remove npm" in script


def test_node_versions_are_pinned_exactly():
    script = (ROOT / "box" / "toolchain.sh").read_text(encoding="utf-8")
    packages = re.findall(r"^\s+(@?[a-z][\w./-]*@\S+)", script, re.MULTILINE)
    assert packages, "no npm packages found"
    for spec in packages:
        version = spec.rsplit("@", 1)[1].rstrip("\\").strip()
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), spec


SKILLS = ROOT / "box" / "platform_skills"


def _tree_hash(root: Path) -> str:
    """The same hash as magenticx's scripts/platform_skills.py (SOURCE excluded),
    ordered by the path string: ``Path`` objects sort case-insensitively on
    Windows and case-sensitively on Linux."""
    digest = hashlib.sha256()
    files = {p.relative_to(root).as_posix(): p for p in root.rglob("*")
             if p.is_file() and p.name != "SOURCE" and "__pycache__" not in p.parts}
    for rel in sorted(files):
        digest.update(rel.encode() + b"\0")
        digest.update(files[rel].read_bytes() + b"\0")
    return digest.hexdigest()


def test_the_platform_skills_are_the_tree_source_records():
    """The box carries magenticx's platform skills byte for byte (plan 44): the
    agent reads a SKILL.md there and runs its scripts here, at the same path.
    A mismatch means the two copies drifted: rebuild in magenticx and copy."""
    source = dict(line.split(" ", 1) for line in (SKILLS / "SOURCE").read_text(encoding="utf-8").splitlines())
    assert source["repo"] == "https://github.com/anthropics/skills"
    assert source["tree"] == _tree_hash(SKILLS)
    for name in ("docx", "xlsx", "pptx", "pdf"):
        assert (SKILLS / name / "SKILL.md").is_file() and (SKILLS / name / "LICENSE.txt").is_file()


def test_both_dockerfiles_put_the_skills_at_the_agents_path():
    box = (ROOT / "box" / "Dockerfile").read_text(encoding="utf-8")
    runner = _box_stage((ROOT / "runner" / "Dockerfile").read_text(encoding="utf-8"))
    assert "COPY platform_skills /platform_skills" in box
    assert "COPY box/platform_skills /platform_skills" in runner
