from pathlib import Path
from urllib.parse import unquote, urlparse


def artifact_state(uri: str | None) -> str:
    if not uri or not uri.strip():
        return "missing"
    value = uri.strip()
    parsed = urlparse(value)
    windows_drive_path = len(value) >= 3 and value[1] == ":" and value[2] in {"/", "\\"}
    if parsed.scheme and parsed.scheme not in {"file"} and not windows_drive_path:
        return "unverified"
    try:
        if parsed.scheme == "file":
            raw_path = unquote(parsed.path)
            if parsed.netloc:
                raw_path = f"//{parsed.netloc}{raw_path}"
            if len(raw_path) >= 3 and raw_path[0] == "/" and raw_path[2] == ":":
                raw_path = raw_path[1:]
            path = Path(raw_path)
        else:
            path = Path(value)
        return "available" if path.expanduser().resolve().is_file() else "missing"
    except (OSError, ValueError):
        return "missing"
