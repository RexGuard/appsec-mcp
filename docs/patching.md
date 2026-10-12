# Patching and hardening

The tool only writes to your project through `apply_patch`, and only with a token from a proposal
you have seen.

## The flow

1. `propose_patch(finding_id)` or `propose_hardening(scan_id, recipe)` builds the change in memory
   and returns a unified diff, a plain-language summary and a `proposal_token`. **Nothing is
   written.**
2. You read the diff and say yes.
3. `apply_patch(proposal_token)`:
   - refuses if the token is unknown, already used, or older than 30 minutes
   - refuses if any target file changed since the proposal (`FILES_CHANGED_SINCE_PROPOSAL`)
   - copies the originals to `~/.appsec-mcp/backups/<patch id>/`
   - writes each file atomically; if any write fails, everything is restored (`WRITE_FAILED`)
4. Re-scan: the finding shows as **fixed**.
5. `revert_patch(patch_id)` restores the originals byte for byte and deletes files the patch
   created. If you edited the files after applying, it refuses unless you pass `force=true`.

## Automatic fixes

| Finding | Fix |
|---|---|
| Hard-coded secret (JS/TS/Python) | Read it from an environment variable, list the name in `.env.example`, ignore `.env` in git. Rotate the key afterwards: it was already exposed. |
| SQL built from strings (simple JS/Python shapes) | Parameterised query (`?`, `%s` or `$1` depending on the driver) |
| Flask/Django debug on | `debug=False` |
| CORS `*` | Allow-list from `ALLOWED_ORIGINS` |
| `strcpy` | `snprintf(dst, sizeof(dst), "%s", src)` (correct only for array destinations) |
| `gets` | `fgets(buf, sizeof(buf), stdin)` |
| `.env` not ignored | Add `.env` to `.gitignore` |
| Missing security headers / CSRF | Runs the matching recipe below |

Anything else returns `NOT_PATCHABLE` with manual fix advice.

## Recipes ("add a security layer")

`list_recipes(scan_id)` shows which ones fit your project and why.

| Recipe | Express | Next.js | Flask | FastAPI | Spring Boot |
|---|---|---|---|---|---|
| `security_headers` | helmet | `middleware.ts` | `after_request` hook | HTTP middleware | `OncePerRequestFilter` |
| `rate_limit` | express-rate-limit | | Flask-Limiter | | |
| `csrf` | Origin check middleware | | Flask-WTF `CSRFProtect` | | (on by default with Spring Security) |
| `env_secrets` | any project | any | any | any | any |
| `input_validation` | `express.json` size limit | | `MAX_CONTENT_LENGTH` | | |

Empty cells report "not applicable" with advice for that framework. Recipes that add a package
also add it to `package.json` or `requirements.txt`; run your installer afterwards.
