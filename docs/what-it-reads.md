# What it reads: the audit ledger

Every scan records exactly what it looked at, so the result is not a black box. Ask your assistant
*"what did you read?"* (`get_audit_ledger`) or open the Ledger tab in `appsec-mcp view`.

## Files

Every path under the scan root ends up in the ledger as **read** or **skipped**.

- **Read** files are stored with their language, size and SHA-256 hash. The hash lets you prove
  later which exact version of a file was scanned.
- **Skipped** paths carry a reason:

| Reason | Meaning |
|---|---|
| `excluded_dir` | A dependency or build folder (`node_modules`, `.git`, `dist`, `build`, `venv`, `target`, ...). Recorded once, not entered. |
| `gitignored` | Matched by a `.gitignore` or `.appsecignore` file. |
| `too_large` | Bigger than `max_file_kb` (default 1024 KB). |
| `binary` | Contains null bytes, so it is not source code. |
| `symlink_outside_root` | A link pointing outside the project. Never followed. |
| `symlink_dir` | A linked folder. Not followed, to avoid loops. |
| `unreadable` | The operating system refused to open it. |

## Rules and scanners

- **Rules applied**: every rule each scanner ran, with how many files it matched. A rule with 0
  matches still ran; that is useful evidence too.
- **Scanners**: which scanners ran (with version and time), and which were skipped with the reason
  and an install hint.

## What never leaves your machine

Nothing is uploaded. Secret values are masked (for example `sk_live_****abcd`) before anything is
stored or returned, so even the database and the AI conversation only see the masked form.

## The system map

`get_system_map` turns the files that were read into a picture of the app:

- **components**: folders with source code
- **entry points**: files that start the program (`app.listen`, `if __name__ == "__main__"`,
  `main()`, `index.html`)
- **routes**: Express, Next.js, Flask, FastAPI and Spring endpoints
- **data stores** and **external services**: from imports, JDBC URLs and HTTP calls
- **secrets**: where a secret was found
- **dependencies**: from `package.json`, `requirements.txt`, `pom.xml`, Gradle, CMake, vcpkg, conan

Nodes with findings are highlighted as hotspots. Frameworks it does not know still appear as
components.
