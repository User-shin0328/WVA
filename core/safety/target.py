"""Canonical entry URLs and path boundaries shared by every scan entry point."""
import posixpath
from urllib.parse import unquote, urlsplit, urlunsplit


def decoded_path(path: str) -> str:
    value = path or "/"
    for _ in range(6):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    if "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("경로의 제어 문자와 역슬래시는 사용할 수 없습니다.")
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("경로의 . 또는 .. 부분을 정리한 URL을 입력하세요.")
    return posixpath.normpath("/" + value.lstrip("/"))


def normalize_target_url(value: str) -> str:
    value = value.strip()
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("주소의 공백·제어 문자·역슬래시를 확인하세요.")
    try:
        p = urlsplit(value)
        port = p.port
    except ValueError as exc:
        raise ValueError("서버 주소와 포트 번호를 확인하세요.") from exc
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("http:// 또는 https://로 시작하는 진단 URL을 입력하세요.")
    if p.username is not None or p.password is not None:
        raise ValueError("URL에 아이디·비밀번호를 포함할 수 없습니다. 인증정보가 없는 URL을 입력하세요.")
    if port == 0:
        raise ValueError("1~65535 사이의 포트를 입력하세요.")
    if p.fragment:
        raise ValueError("# 뒤의 화면 위치는 서버로 전송되지 않습니다. 해당 부분을 제외하세요.")
    decoded_path(p.path)
    # Root-only URLs retain their previous spelling; a path/query is never stripped.
    return urlunsplit((p.scheme, p.netloc, p.path if p.path != "/" or p.query else "", p.query, ""))
