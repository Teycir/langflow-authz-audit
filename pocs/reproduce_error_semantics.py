#!/usr/bin/env python3
"""Reproducer: authorization-denial errors surfaced as 200/500 instead of 404.

Non-destructive: only GET requests and one read-only POST (files batch download).
Proves three defects on a stock Langflow (v1.13.2-16-g86fde091f8) instance:

  F1  GET /api/v1/mcp/project/{id}/composer-url  -> 200 for a project the caller
      does not own (verify_project_access raises 404, get_project_composer_url
      swallows it in a broad `except Exception`).
  F2  GET /api/v1/mcp/project/{id}/installed     -> 500 "404: Project not found".
  F3  POST /api/v2/files/batch/                  -> 500 "Error downloading files:
      404: No files found" for foreign/unknown file ids.

Usage:
  python3 reproduce_error_semantics.py \
      --base http://127.0.0.1:7860 \
      --attacker-token "$TOK_ATTACKER" \
      --owner-token  "$TOK_OWNER" \
      --project-id 6fc8d7dd-3079-44b0-8383-e82e0789d879 \
      --file-id eb93ce70-c0a2-4393-868c-d9a9d2f74fa5

Exit code 0 = all three defects reproduced, 1 = mismatch.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import uuid


def req(method: str, url: str, token: str, body: bytes | None = None) -> tuple[int, str]:
    r = urllib.request.Request(url, data=body, method=method, headers={"Authorization": f"Bearer {token}"})
    if body is not None:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=25) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--attacker-token", required=True)
    ap.add_argument("--owner-token", required=True)
    ap.add_argument("--project-id", required=True)
    ap.add_argument("--file-id", required=True)
    a = ap.parse_args()
    base = a.base.rstrip("/")
    rand = str(uuid.uuid4())
    failures = 0

    def check(name: str, cond: bool, detail: str) -> None:
        nonlocal failures
        print(f"[{'PASS' if cond else 'FAIL'}] {name}: {detail}")
        if not cond:
            failures += 1

    # F1 — 404 swallowed into 200, indistinguishable from a real failure
    c1, b1 = req("GET", f"{base}/api/v1/mcp/project/{a.project_id}/composer-url", a.attacker_token)
    c1r, b1r = req("GET", f"{base}/api/v1/mcp/project/{rand}/composer-url", a.attacker_token)
    c1o, b1o = req("GET", f"{base}/api/v1/mcp/project/{a.project_id}/composer-url", a.owner_token)
    check("F1 attacker/victim not 404", c1 == 200, f"HTTP {c1} {b1[:100]}")
    check("F1 attacker/random not 404", c1r == 200, f"HTTP {c1r} {b1r[:100]}")
    check("F1 attacker bodies identical shape", ("error_message" in b1 and "error_message" in b1r),
          "both carry the swallow-all error_message")
    check("F1 owner control healthy", c1o == 200 and "streamable_http_url" in b1o and "error_message\":null" in b1o,
          f"HTTP {c1o}")

    # F2 — 404 converted to 500 with the denial reason in the body
    c2, b2 = req("GET", f"{base}/api/v1/mcp/project/{a.project_id}/installed", a.attacker_token)
    c2o, _ = req("GET", f"{base}/api/v1/mcp/project/{a.project_id}/installed", a.owner_token)
    check("F2 foreign project -> 500", c2 == 500 and "404: Project not found" in b2, f"HTTP {c2} {b2[:80]}")
    check("F2 owner control 200", c2o == 200, f"HTTP {c2o}")

    # F3 — foreign file id -> 500 wrapping the internal 404
    body = json.dumps([a.file_id]).encode()
    c3, b3 = req("POST", f"{base}/api/v2/files/batch/", a.attacker_token, body)
    c3o, b3o = req("POST", f"{base}/api/v2/files/batch/", a.owner_token, body)
    check("F3 foreign file -> 500 leak", c3 == 500 and "Error downloading files: 404" in b3, f"HTTP {c3} {b3[:90]}")
    check("F3 owner control 200 zip", c3o == 200 and b3o.startswith("PK"), f"HTTP {c3o}")

    print(f"\n{'ALL THREE DEFECTS REPRODUCED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
