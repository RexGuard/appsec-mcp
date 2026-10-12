# UI review (T5 checkpoint)

Phase 1 is built: the viewer shows Findings, System map and Audit ledger from sample data
(`viewer/src/mock/*.json`, modelled on a scan of `tests/fixtures/vuln_apps/express_app`).
Backend work (T6 onward) starts after this review.

## How to run it

```bash
cd viewer
npm install
npm run dev            # http://127.0.0.1:5173
# Stress test the map with a synthetic 300-node graph:
# http://127.0.0.1:5173/?big=300#/map
```

## What to check

- **Findings:** is the plain-language text right for a non-security user? Is the score card useful?
  Should severity chips filter (current) or only show counts?
- **System map:** are the node kinds and colours clear? Is the side panel (problems + connections) what
  you want when clicking a node? Is 300 nodes still usable?
- **Audit ledger:** is "read / skipped with reason / checks that ran" enough to trust the result?
- **Wording and layout** anywhere else.

## Decisions

| Date | Decision | By |
|---|---|---|
| | _pending review_ | |

## Frozen contract

Once approved, the shapes in `viewer/src/mock/*.json` are the HTTP API contract. They are already
validated on both sides: Zod (`viewer/src/api/schemas.test.ts`) and Pydantic
(`tests/models/test_viewer_contract.py`).
