# UI review (T5 checkpoint)

Status: **waiting for Erick's review.** The viewer was built and checked on live data
(`appsec-mcp view` after scanning the express and flask fixtures): all three tabs load, the token is
removed from the address bar after the first load, and the browser console shows no errors.

## What to click through

- **Findings**: score, severity counts, filter by severity and text, click a finding for
  "What it is / Why it matters / How to fix it", the masked snippet and whether an automatic fix
  exists.
- **Map**: graph coloured by node kind, risky nodes with red borders, click a node for its files
  and findings; "Show all dependencies" reveals clean dependency nodes.
- **Ledger**: scanners run and skipped (with install hints), rules applied with match counts, and
  every file read (SHA-256) or skipped (reason), 200 per page.

## Decisions taken so far

- The API contract is the Pydantic models in `src/appsec_mcp/models/`; the viewer validates every
  response with matching Zod schemas in `viewer/src/api/schemas.ts`.
- The token travels in the URL fragment (`#token=`), not the query string, so it never reaches
  server logs or `Referer` headers, and is kept in `sessionStorage` for the tab only.
- Clean dependency nodes are hidden by default to keep big graphs readable.

## Requested changes

(none yet)

## Tester results (T17)

(not run yet: needs three non-security testers to complete Flow 1 and Flow 3)
