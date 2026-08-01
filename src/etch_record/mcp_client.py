"""Minimal MCP client for the single flow we need: post one `record_event`.

Handles the three-step MCP dance:
  1. POST /mcp   {method: "initialize"}         -> session_id in response header
  2. POST /mcp   {method: "notifications/initialized"}
  3. POST /mcp   {method: "tools/call", name: "record_event", arguments: {...}}

Session ID is per-invocation. We do NOT persist it across CLI runs -
each `etch-record` call is a fresh session. That is O(1) events per
invocation, which is fine for CLI usage; a daemon-style caller would
want to keep the session open.

Response format: the Etch /mcp endpoint uses the MCP StreamableHTTP
transport, which serves responses as text/event-stream (SSE) frames
containing the JSON-RPC body inside a `data:` line. For a single
tools/call there is exactly one message frame per response, so we
extract the data payload and parse it as JSON.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from . import __version__
from .config import Config


class McpError(RuntimeError):
    pass


_PROTOCOL_VERSION = "2025-11-05"
_TIMEOUT_SECONDS = 15.0


def _parse_mcp_body(response: httpx.Response) -> dict:
    """Return the JSON-RPC body from an MCP response.

    Handles both content types the MCP StreamableHTTP transport spec
    permits:
      - application/json (plain JSON body)
      - text/event-stream (SSE frames; the JSON is inside data: lines)

    For SSE, we concatenate all `data:` lines in the response (per the
    SSE spec: a single message split across multiple data lines is
    reassembled by joining with newlines) and parse the result.
    Returns the parsed JSON-RPC message dict.
    """
    content_type = (response.headers.get("content-type") or "").lower()
    text = response.text

    is_sse = (
        "text/event-stream" in content_type
        or text.lstrip().startswith("event:")
        or text.lstrip().startswith("data:")
    )
    if is_sse:
        data_parts: list[str] = []
        for raw in text.splitlines():
            if raw.startswith("data:"):
                # Per SSE spec: strip leading "data:" then a single
                # optional space. Do not strip further whitespace so
                # JSON with intentional leading spaces round-trips.
                chunk = raw[len("data:"):]
                if chunk.startswith(" "):
                    chunk = chunk[1:]
                data_parts.append(chunk)
        if not data_parts:
            raise McpError(
                f"SSE response contained no data lines: {text[:200]!r}",
            )
        joined = "\n".join(data_parts)
        try:
            return json.loads(joined)
        except json.JSONDecodeError as exc:
            raise McpError(
                f"SSE data was not valid JSON: {joined[:200]!r}",
            ) from exc

    # Plain JSON response.
    try:
        return response.json()
    except json.JSONDecodeError as exc:
        raise McpError(
            f"non-JSON response ({content_type or 'no content-type'}): "
            f"{text[:200]!r}",
        ) from exc


def extract_event_id(body: dict) -> str | None:
    """Pull the Etch server's event_id out of a tools/call result body.

    Etch's record_event tool returns a nested JSON string inside
    result.content[0].text, shaped like:
        {"event_id": "uuid", "status": "recorded"}
    This peels the two layers and returns the inner event_id. Returns
    None if the shape doesn't match (call sites should fall back to
    the JSON-RPC message id or "?").
    """
    try:
        content = body.get("result", {}).get("content") or []
        if not content:
            return None
        first = content[0]
        text = first.get("text") if isinstance(first, dict) else None
        if not text:
            return None
        inner = json.loads(text)
        eid = inner.get("event_id")
        return str(eid) if eid is not None else None
    except (json.JSONDecodeError, AttributeError, TypeError, IndexError):
        return None


def _headers_for(cfg: Config, mcp_session_id: str | None = None) -> dict[str, str]:
    hdrs = {
        "Authorization": f"Bearer {cfg.app_token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    if mcp_session_id:
        hdrs["mcp-session-id"] = mcp_session_id
    return hdrs


def _initialize(client: httpx.Client, cfg: Config) -> str:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "etch-record", "version": __version__},
        },
    }
    r = client.post("/mcp", headers=_headers_for(cfg), json=payload)
    if r.status_code != 200:
        raise McpError(f"initialize failed: {r.status_code} {r.text[:200]}")
    sid = r.headers.get("mcp-session-id")
    if not sid:
        raise McpError("initialize response missing mcp-session-id header")
    return sid


def _notify_initialized(client: httpx.Client, cfg: Config, sid: str) -> None:
    payload = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    r = client.post("/mcp", headers=_headers_for(cfg, sid), json=payload)
    # 202 is the expected response for notifications; 200 also fine.
    if r.status_code not in (200, 202):
        raise McpError(
            f"notifications/initialized failed: {r.status_code} {r.text[:200]}"
        )


def record_event(cfg: Config, arguments: dict[str, Any]) -> dict[str, Any]:
    """Post one record_event tool call. Returns the parsed JSON result."""
    with httpx.Client(base_url=cfg.base_url, timeout=_TIMEOUT_SECONDS) as client:
        sid = _initialize(client, cfg)
        _notify_initialized(client, cfg, sid)

        payload = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "record_event", "arguments": arguments},
        }
        r = client.post("/mcp", headers=_headers_for(cfg, sid), json=payload)
        if r.status_code != 200:
            raise McpError(
                f"tools/call failed: {r.status_code} {r.text[:200]}"
            )
        body = _parse_mcp_body(r)
        if "error" in body:
            raise McpError(f"MCP error: {body['error']}")
        return body
