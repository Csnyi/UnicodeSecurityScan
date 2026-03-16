# Unicode Security Scan

A lightweight repository scanner for detecting suspicious Unicode characters and risky identifiers in source files.

This tool helps identify:

- Trojan Source style bidirectional control characters
- zero-width / invisible Unicode characters
- suspicious non-ASCII identifiers
- mixed-script identifiers (e.g. Latin + Cyrillic lookalikes)

It is intended for repository auditing, dependency inspection, and CI security checks.

---

## Why this exists

Unicode characters can visually disguise code behavior.

Some characters:

- are invisible
- can reorder text visually
- can create identifiers that look identical but are different

Examples include Trojan Source attacks and homoglyph attacks.

This scanner helps surface those issues early.

---

## What it checks

### 1. Bidirectional control characters

Examples:

- `U+202A` LEFT-TO-RIGHT EMBEDDING
- `U+202B` RIGHT-TO-LEFT EMBEDDING
- `U+202D` LEFT-TO-RIGHT OVERRIDE
- `U+202E` RIGHT-TO-LEFT OVERRIDE
- `U+2066` LEFT-TO-RIGHT ISOLATE
- `U+2067` RIGHT-TO-LEFT ISOLATE
- `U+2068` FIRST STRONG ISOLATE
- `U+2069` POP DIRECTIONAL ISOLATE

These are commonly used in Trojan Source style attacks.

### 2. Zero-width / invisible characters

Examples:

- `U+200B` ZERO WIDTH SPACE
- `U+200C` ZERO WIDTH NON-JOINER
- `U+200D` ZERO WIDTH JOINER
- `U+2060` WORD JOINER
- `U+FEFF` ZERO WIDTH NO-BREAK SPACE / BOM

### 3. Non-ASCII identifiers

Identifiers containing non-ASCII characters are flagged for review.

### 4. Mixed-script identifiers

Identifiers combining multiple writing systems are suspicious.

Example:

```text
paylоad
```

Here the `o` may be Cyrillic instead of Latin.

---

## Severity levels

Findings are classified by severity.

| Level | Meaning |
|---|---|
| `ERROR` | High-risk Unicode issue in project code — blocks CI by default |
| `WARN` | Suspicious pattern that should be reviewed |
| `AUDIT` | Found in third-party code — warrants review but does not block CI |
| `INFO` | Likely harmless, e.g. in minified bundles or localization files |

### Severity by finding type and file context

| Finding | Executable (`.js`, `.py` …) | Third-party (`node_modules/`, `vendor/` …) | Trusted noise (`tests/`, `locale/`, `.md` …) |
|---|---|---|---|
| BIDI / zero-width / `Cf` char | `ERROR` | `AUDIT` | `WARN` |
| Unexpected control char (`Cc`) | `WARN` | `INFO` | `INFO` |
| Mixed-script identifier | `ERROR` | `ERROR` | `ERROR` |
| Non-ASCII identifier | `WARN` | `AUDIT` | `INFO` |
| Suspicious import path | `ERROR` | `ERROR` | `n/a` |

---

## File risk profiles

The scanner classifies each file into one of four profiles, which affects severity levels.

| Profile | Paths / extensions | Treatment |
|---|---|---|
| `executable` | `.js`, `.ts`, `.py`, `.sh`, `.html`, `.css` … | Strict — full severity |
| `third_party` | `node_modules/`, `site-packages/`, `vendor/`, `extern/` … | Auditable — `BIDI`/`ZERO_WIDTH` downgraded to `AUDIT` |
| `trusted_noise` | `tests/`, `locale/`, `lang/`, `i18n/`, `data/`, `.json`, `.yml`, `.md` … | Lenient — `BIDI`/`ZERO_WIDTH` downgraded to `WARN` |
| `neutral` | Everything else | Same as `executable` |

---

## Usage

Run from the repository root:

```bash
python tools/unicode_security_scan.py
```

Specify a directory:

```bash
python tools/unicode_security_scan.py .
```

Include `node_modules` (scanned as `third_party`):

```bash
python tools/unicode_security_scan.py --include-node-modules
```

Include `node_modules` but only block on project-file errors:

```bash
python tools/unicode_security_scan.py --include-node-modules --fail-on project-only
```

Output results as JSON:

```bash
python tools/unicode_security_scan.py --json
python tools/unicode_security_scan.py --json | jq '.findings[] | select(.severity == "ERROR")'
```

---

## Example output

### Human-readable

```text
Scanned: /home/user/project
Include node_modules: no
Files scanned: 42
Workers: 8

src/app.js:18:14  [ERROR] [CHAR] ZERO_WIDTH 0x200b ZERO WIDTH SPACE [executable]
    const token​Id = payload.tokenId;

src/app.js:18:11  [WARN] [IDENT] NON_ASCII_IDENTIFIER: 'token​Id' [executable]
    const token​Id = payload.tokenId;

node_modules/some-lib/index.js:4:9  [AUDIT] [CHAR] BIDI_CONTROL 0x202e RIGHT-TO-LEFT OVERRIDE [third_party]
    exports.verify = /* ... */

node_modules/html5-qrcode.min.js:1:75335  [INFO] [CHAR] Cc 0x7f UNKNOWN [third_party, minified-like]
    var __Html5QrcodeLibrary__=...
```

### JSON (`--json`)

```json
{
  "scanned": "/home/user/project",
  "include_node_modules": false,
  "files_scanned": 42,
  "blocked": true,
  "summary": {
    "total": 3,
    "by_severity": { "ERROR": 1, "WARN": 1, "AUDIT": 1 },
    "by_kind": { "CHAR": 2, "IDENT": 1 },
    "by_risk_profile": { "executable": 2, "third_party": 1 },
    "project_files": 2,
    "third_party": 1,
    "minified_like": 0
  },
  "findings": [
    {
      "path": "src/app.js",
      "line": 18,
      "col": 14,
      "kind": "CHAR",
      "severity": "ERROR",
      "risk_profile": "executable",
      "details": "ZERO_WIDTH 0x200b ZERO WIDTH SPACE",
      "snippet": "    const token​Id = payload.tokenId;",
      "is_minified_like": false
    }
  ]
}
```

---

## Notes about third-party code

Third-party code (`node_modules/`, `site-packages/`, `vendor/` etc.) is treated as **auditable foreign code**, not trusted noise. It receives its own `AUDIT` severity level so that genuine issues remain visible without blocking the CI pipeline.

Control characters inside minified bundles are still reported as `INFO` to reduce noise.

---

## Exit codes

- `0` → no blocking issues found
- `1` → one or more blocking issues found according to the selected failure policy

By default, only `ERROR` findings are blocking. `AUDIT` findings are never blocking.

---

## Recommended workflow

### Local development

```bash
python tools/unicode_security_scan.py
```

### Dependency audit

```bash
python tools/unicode_security_scan.py --include-node-modules --fail-on project-only
```

### CI pipeline

```bash
# Strict check on project files only
python tools/unicode_security_scan.py --fail-on project-only

# Save full results for later review
python tools/unicode_security_scan.py --include-node-modules --json > unicode-report.json
```

The scanner processes files in parallel using a thread pool (`min(16, cpu_count × 2)` workers), so it stays fast even on large repositories.

---

## Git pre-commit hook example

`.git/hooks/pre-commit`

```sh
#!/bin/sh
python tools/unicode_security_scan.py

if [ $? -ne 0 ]; then
  echo "Suspicious Unicode detected. Commit aborted."
  exit 1
fi
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

---

## Typical benign sources

Findings are often caused by:

- copy-paste from Word, Slack, Notion, PDFs, or chats
- documentation formatting
- localization text
- generated bundles

However:

- BIDI characters in source code are high risk
- zero-width characters in identifiers are high risk
- mixed-script identifiers deserve review

---

## Limitations

This tool intentionally stays lightweight.

It detects:

- Trojan Source characters
- invisible Unicode characters
- suspicious identifier patterns
- basic mixed-script issues

It is not a full Unicode confusables engine, so extremely subtle homoglyph attacks may not always be detected.

---

## Suggested repository structure

```text
tools/
  unicode_security_scan.py
```

Optional:

```text
.github/workflows/unicode-scan.yml
SECURITY.md
```

---

## License

Use the same license as the parent repository.
