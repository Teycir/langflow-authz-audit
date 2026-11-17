# Langflow AuthZ Audit — `v1.13.2-16-g86fde091f8`

Two-principal differential authorization audit of a self-hosted Langflow instance.
All testing non-destructive (GET / read-only POST). Result: **no bounty-grade vulnerability**;
three informational error-mapping defects proven, ~30 cross-tenant access attempts falsified.

- Engagement (source of truth): `~/BugBounty/langflow/20261117/184807/`
- Audit date: 2026-11-17 (UTC)
- Target: Langflow `v1.13.2-16-g86fde091f8`, backend-only, SQLite, `http://127.0.0.1:7860`
- Principals: `admin` (superuser, victim-resource owner) vs `attacker` (`5bedaa71-f39b-4755-8f69-30701e094253`, non-superuser)
- Victim resources: flow `a127ad16-f00f-4177-b59d-a55a47320440`, project `6fc8d7dd-3079-44b0-8383-e82e0789d879`, file `eb93ce70-c0a2-4393-868c-d9a9d2f74fa5` (`victim-secret.txt`, sha256 `e5c387ca…1c57526`)

## Findings

| ID | Severity | CVSS 3.1 | CWE | Title |
|----|----------|----------|-----|-------|
| RT-01 | Informational | 0.0 | CWE-755/209 | `GET /api/v1/mcp/project/{id}/composer-url` swallows 404 into HTTP 200 |
| RT-02 | Informational | 0.0 | CWE-755 | `GET /api/v1/mcp/project/{id}/installed` converts 404 into 500 |
| RT-03 | Informational | 0.0 | CWE-755/209 | `POST /api/v2/files/batch/` converts foreign-file 404 into 500 + internal detail |

Root cause is systemic, not a broken permission model: broad `except Exception` in
`api/v1/mcp_projects.py` (`get_project_composer_url`, `check_installed_mcp_servers`) and
`api/v2/files.py` (`download_files_batch`) rewrites authorization denials.

## Proofs (verbatim, UTC 2026-11-17T19:01:53Z / 19:02:01Z)

RT-01 — attacker token, **foreign** project → 200, indistinguishable from unknown project:
```json
{"project_id":"6fc8d7dd-3079-44b0-8383-e82e0789d879","uses_composer":true,"streamable_http_url":null,"legacy_sse_url":null,"error_message":"Failed to get MCP Composer URL. See logs for details."}
```
Owner control → real config, `error_message:null`, `streamable_http_url` populated.

RT-02 — attacker token:
```http
HTTP/1.1 500 Internal Server Error
{"detail":"404: Project not found"}
```
Owner control → `200 [{"name":"cursor",...}]`.

RT-03 — attacker token, body `["eb93ce70-c0a2-4393-868c-d9a9d2f74fa5"]`:
```http
HTTP/1.1 500 Internal Server Error
{"detail":"Error downloading files: 404: No files found"}
```
Owner control → `200`, zip containing `victim-secret.txt` / `IDOR-VICTIM-SECRET-1794941259`.
Attacker received no file bytes.

## Reproduce

Prereqs: live instance, owner + attacker tokens, victim project/file UUIDs (above).

```bash
python3 pocs/reproduce_error_semantics.py \
  --base http://127.0.0.1:7860 \
  --attacker-token "$ATK" --owner-token "$OWN" \
  --project-id 6fc8d7dd-3079-44b0-8383-e82e0789d879 \
  --file-id eb93ce70-c0a2-4393-868c-d9a9d2f74fa5
```
Last run: 8/8 checks PASS, exit 0 (`evidence/poc_run_20261117T190327Z.log`).

## Falsified (negative controls, all denied; owner controls pass)

Flows get/list/download, `/run/{id|name}` and `/run/advanced` (JWT → 403; attacker API key → 404),
`/webhook/{flow}` (403), `/webhook-events/{flow}` (403 JWT, 404 API key), files v1/v2,
projects/folders/deployment-snapshot, MCP project + servers, traces, messages, variables,
knowledge-base-storage inventory (403). Details: report §5.3.

Residual untested: legacy `/api/v1/mcp/sse`, `POST /api/v1/responses`, OAuth broker `complete`,
`v1/migration.py` dependencies.

## Layout

```
report_20261117_190231.md   full PTES/OWASP-style report, Status FINAL
pocs/reproduce_error_semantics.py
SHA256SUMS                  report + PoC hashes (repo root)
evidence/                   70 artifacts: request/response pairs, timeline, redacted key JSON
evidence/SHA256SUMS         evidence-only manifest (paths relative to evidence/)
evidence/report.sha256      report self-hash
```

Secrets (JWTs, `sk-` API keys) redacted before publication; no credentials in this repo.

## Integrity

```bash
sha256sum -c SHA256SUMS                          # report + PoC (repo root)
(cd evidence && sha256sum -c SHA256SUMS)         # all evidence artifacts
sha256sum -c evidence/report.sha256               # report self-hash
```

## Fix

Re-raise `HTTPException` before generic handling in the three handlers; map per-file denials to
404/207 with neutral text; add a CI test asserting every `verify_*`/`ensure_*` denial yields 403/404.
