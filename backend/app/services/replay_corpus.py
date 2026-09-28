"""Sandbox input validation.

The rule sandbox hands a caller-supplied PCAP path to an external binary
(``suricata -r <path>``). Without validation that is a local file disclosure
primitive: an attacker with rule-deploy rights could point the replay at
``/etc/shadow`` (or, on Windows, any readable file) and then read the parsed
output through the sandbox run's ``detail``. Every path therefore has to resolve
inside the configured corpus root, exist, and carry a PCAP suffix.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ALLOWED_SUFFIXES = (".pcap", ".pcapng", ".cap")
MAX_PATH_LENGTH = 1_000


class CorpusPathError(ValueError):
    """Raised when a replay path is missing, out of the corpus, or not a PCAP."""


@dataclass(frozen=True, slots=True)
class ValidatedCapture:
    requested: str
    resolved: Path
    size_bytes: int


def validate_capture_path(raw: str | None, *, corpus_root: str | Path) -> ValidatedCapture | None:
    """Validate one replay capture path, or return None when it was not provided.

    Rejects: absolute/relative traversal outside the corpus, symlinks that escape
    it, non-PCAP suffixes, directories, empty files and over-long paths.
    """
    if raw is None or not str(raw).strip():
        return None
    candidate = str(raw).strip()
    if len(candidate) > MAX_PATH_LENGTH:
        raise CorpusPathError(f"path is longer than {MAX_PATH_LENGTH} characters")
    if "\x00" in candidate:
        raise CorpusPathError("path contains a NUL byte")
    corpus = Path(corpus_root).expanduser().resolve()
    path = Path(candidate)
    resolved = (corpus / path).resolve() if not path.is_absolute() else path.expanduser().resolve()
    if not _inside(resolved, corpus):
        raise CorpusPathError(
            f"replay capture must live inside the corpus root ({corpus}); got {resolved}"
        )
    if resolved.suffix.lower() not in ALLOWED_SUFFIXES:
        raise CorpusPathError(f"replay capture must end with one of {list(ALLOWED_SUFFIXES)}")
    if not resolved.is_file():
        raise CorpusPathError(f"replay capture was not found: {resolved}")
    size = resolved.stat().st_size
    if size <= 0:
        raise CorpusPathError(f"replay capture is empty: {resolved}")
    return ValidatedCapture(requested=candidate, resolved=resolved, size_bytes=size)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def corpus_summary(corpus_root: str | Path) -> dict[str, object]:
    """Inventory of the replay corpus (used by the capability endpoint)."""
    corpus = Path(corpus_root).expanduser().resolve()
    if not corpus.is_dir():
        return {
            "root": str(corpus),
            "exists": False,
            "captures": [],
            "note": "回放语料目录不存在：PCAP 回放无法执行，相关验证会保持未测量。",
        }
    captures = sorted(
        {
            str(item.relative_to(corpus)).replace("\\", "/")
            for item in corpus.rglob("*")
            if item.is_file() and item.suffix.lower() in ALLOWED_SUFFIXES
        }
    )
    return {
        "root": str(corpus),
        "exists": True,
        "captures": captures[:200],
        "count": len(captures),
        "note": (
            "语料目录中的 PCAP 可用于沙箱回放。"
            if captures
            else "语料目录为空：缺少标注 PCAP，回放指标会保持未测量。"
        ),
    }
