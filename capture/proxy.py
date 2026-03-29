"""
capture/proxy.py — mitmproxy addon that writes HAR entries to disk.

Install the proxy extra to use this module:
    pip install "apidiff[proxy]"

Usage (via mitmproxy):
    mitmdump -s capture/proxy.py --set har_out=output.har --set filter_host=api.example.com
"""

from __future__ import annotations

import json
import pathlib
import time
from typing import Optional


class HARWriter:
    """mitmproxy addon. Writes every request/response pair to a HAR file.

    Can be used standalone (instantiated directly) or as a mitmproxy addon.
    When used as an addon, mitmproxy calls response() for each completed flow.
    """

    def __init__(self, out_path: str, filter_host: Optional[str] = None) -> None:
        self.out_path = pathlib.Path(out_path)
        self.filter_host = filter_host
        self.entries: list[dict] = []
        self._start = time.time()

    # ── mitmproxy addon hook ──────────────────────────────────────────────────

    def response(self, flow) -> None:  # type: ignore[no-untyped-def]
        """Called by mitmproxy for each completed HTTP flow."""
        if self.filter_host and self.filter_host not in flow.request.host:
            return  # skip traffic to other hosts

        try:
            request_text = flow.request.get_text() or ""
        except Exception:
            request_text = ""

        try:
            response_text = flow.response.get_text() or ""
        except Exception:
            response_text = ""

        entry = {
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": dict(flow.request.headers),
                "postData": {"text": request_text},
            },
            "response": {
                "status": flow.response.status_code,
                "headers": dict(flow.response.headers),
                "content": {"text": response_text},
            },
            "timings": {"receive": (time.time() - self._start) * 1000},
        }
        self.entries.append(entry)

    def done(self) -> None:
        """Called by mitmproxy when capture is complete. Writes the HAR file."""
        self._write()

    # ── public API ────────────────────────────────────────────────────────────

    def add_entry(self, entry: dict) -> None:
        """Add a pre-built HAR entry dict directly (used by replay mode)."""
        self.entries.append(entry)

    def write(self) -> None:
        """Write HAR to disk immediately (used programmatically)."""
        self._write()

    def _write(self) -> None:
        har = {"log": {"version": "1.2", "entries": self.entries}}
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self.out_path.write_text(json.dumps(har, indent=2), encoding="utf-8")
        print(f"Wrote {len(self.entries)} entries to {self.out_path}")


# ── mitmproxy addon wiring ────────────────────────────────────────────────────

def start_proxy(out_path: str, filter_host: Optional[str], port: int) -> None:
    """Launch mitmproxy in the current process (requires apidiff[proxy])."""
    try:
        from mitmproxy.tools.main import mitmdump  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "mitmproxy is required for proxy mode. "
            "Install it with: pip install 'apidiff[proxy]'"
        ) from exc

    args = [
        "--listen-port", str(port),
        "--scripts", __file__,
        "--set", f"har_out={out_path}",
    ]
    if filter_host:
        args += ["--set", f"filter_host={filter_host}"]
    mitmdump(args)
