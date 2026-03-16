# Security Policy

## Unicode Safety

This repository uses automated scanning to detect suspicious Unicode characters in source code.

The following issues are considered **high-risk**:

- Bidirectional control characters (Trojan Source style attacks)
- Zero-width / invisible Unicode characters inside code
- Mixed-script identifiers
- Unexpected control characters

These characters can:

- visually reorder code
- hide characters inside identifiers
- create identifiers that look identical but behave differently

---

## Automated checks

The repository includes a scanner:

```
tools/unicode_security_scan.py
```

Run locally:

```
python tools/unicode_security_scan.py
```

CI systems may also run:

```
python tools/unicode_security_scan.py --include-node-modules --fail-on project-only
```

This audits third-party dependencies while preventing false positives from breaking builds.

---

## Reporting a security issue

If you discover a potential security issue:

1. Do **not open a public issue immediately**
2. Contact the maintainers privately if possible
3. Provide:
   - affected file(s)
   - description of the issue
   - reproduction steps

Responsible disclosure is appreciated.

---

## Dependency hygiene

Because third-party packages may contain unsafe Unicode:

- periodically audit dependencies
- scan `node_modules` when reviewing packages
- prefer trusted and maintained packages

Example audit command:

```
python tools/unicode_security_scan.py --include-node-modules
```

---

## Developer guidelines

When writing code:

- Prefer ASCII identifiers
- Avoid typographic characters in code
- Be cautious when copying code from documents or chat systems

---

## Disclaimer

This scanner improves visibility but does not replace:

- code review
- dependency security practices
- secure development workflows