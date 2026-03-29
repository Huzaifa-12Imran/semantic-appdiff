"""
capture/replay.py — replays a seed HAR file against a target URL.

Guarantees identical inputs between v1 and v2 by replaying the same
requests recorded in a seed HAR file. Best for CI pipelines.
"""

from __future__ import annotations

import json
import pathlib
import time
import urllib.parse
from typing import Optional

import requests

# Headers to strip before replaying (authentication / host-specific)
_STRIP_HEADERS = frozenset(
    [
        "authorization",
        "cookie",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "keep-alive",
    ]
)


def replay(
    seed_har_path: str,
    target_base_url: str,
    out_path: str,
    delay_ms: int = 50,
    timeout_s: int = 30,
    extra_headers: Optional[dict[str, str]] = None,
) -> pathlib.Path:
    """Replay every request in `seed_har_path` against `target_base_url`.

    Args:
        seed_har_path: Path to the seed HAR file.
        target_base_url: Base URL of the target API, e.g. "http://api-v2:8000".
        out_path: Where to write the output HAR file.
        delay_ms: Milliseconds to wait between requests (default 50ms).
        timeout_s: Per-request timeout in seconds.
        extra_headers: Additional headers to inject (e.g. auth tokens).

    Returns:
        Path to the written output HAR file.
    """
    seed = pathlib.Path(seed_har_path)
    if not seed.exists():
        raise FileNotFoundError(f"Seed HAR not found: {seed_har_path}")

    data = json.loads(seed.read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    target = target_base_url.rstrip("/")
    out_entries: list[dict] = []

    session = requests.Session()

    for entry in entries:
        req = entry.get("request", {})
        method = req.get("method", "GET").upper()
        original_url = req.get("url", "")

        # Re-target the URL to the new host, keep path + query
        new_url = _retarget_url(original_url, target)

        # Strip and rebuild headers
        raw_headers = req.get("headers", {})
        headers = _clean_headers(raw_headers)
        if extra_headers:
            headers.update(extra_headers)

        body = req.get("postData", {}).get("text") or None

        t_start = time.monotonic()
        try:
            resp = session.request(
                method=method,
                url=new_url,
                headers=headers,
                data=body.encode("utf-8") if body else None,
                timeout=timeout_s,
                allow_redirects=False,
            )
            elapsed_ms = (time.monotonic() - t_start) * 1000
            try:
                resp_text = resp.text
            except Exception:
                resp_text = ""

            out_entries.append(
                {
                    "request": {
                        "method": method,
                        "url": new_url,
                        "headers": dict(headers),
                        "postData": {"text": body or ""},
                    },
                    "response": {
                        "status": resp.status_code,
                        "headers": dict(resp.headers),
                        "content": {"text": resp_text},
                    },
                    "timings": {"receive": elapsed_ms},
                }
            )
        except Exception as exc:
            # Record failed requests with status 0
            out_entries.append(
                {
                    "request": {
                        "method": method,
                        "url": new_url,
                        "headers": dict(headers),
                        "postData": {"text": body or ""},
                    },
                    "response": {
                        "status": 0,
                        "headers": {},
                        "content": {"text": f"ERROR: {exc}"},
                    },
                    "timings": {"receive": 0},
                }
            )

        if delay_ms > 0:
            time.sleep(delay_ms / 1000)

    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    har = {"log": {"version": "1.2", "entries": out_entries}}
    out.write_text(json.dumps(har, indent=2), encoding="utf-8")
    print(f"Replay complete: {len(out_entries)} requests → {out}")
    return out


def _retarget_url(original_url: str, target_base: str) -> str:
    """Replace scheme+host in original_url with target_base, keep path+query."""
    parsed = urllib.parse.urlparse(original_url)
    new_parsed = urllib.parse.urlparse(target_base)
    result = parsed._replace(scheme=new_parsed.scheme, netloc=new_parsed.netloc)
    return urllib.parse.urlunparse(result)


def _clean_headers(raw: dict) -> dict:
    """Strip authentication/hop-by-hop headers from a header dict."""
    return {k: v for k, v in raw.items() if k.lower() not in _STRIP_HEADERS}
