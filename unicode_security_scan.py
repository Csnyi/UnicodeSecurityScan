#!/usr/bin/env python3
"""Scan source files for suspicious Unicode characters and mixed-script identifiers."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Iterator


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BIDI_CONTROL_CODES: frozenset[int] = frozenset({
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
})

ZERO_WIDTH_CODES: frozenset[int] = frozenset({
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
})

ALLOWED_CONTROL_CODES: frozenset[int] = frozenset({
    0x09,  # TAB
    0x0A,  # LF
    0x0D,  # CR
})

SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".json", ".jsonc",
    ".html", ".css", ".scss",
    ".md", ".txt",
    ".yml", ".yaml", ".toml", ".ini",
    ".py", ".sh",
})

# Fájltípus-alapú kockázati besorolás
# EXECUTABLE: végrehajtható forráskód – szigorú szabályok
# TRUSTED_NOISE: lokalizáció, dokumentáció – enyhébb szabályok
# NEUTRAL: minden más forrás – alapértelmezett szabályok
EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".mjs", ".cjs", ".jsx",
    ".ts", ".tsx",
    ".py", ".sh",
    ".html", ".css", ".scss",
})

TRUSTED_NOISE_EXTENSIONS: frozenset[str] = frozenset({
    ".json", ".jsonc",
    ".yml", ".yaml",
    ".toml", ".ini",
    ".md", ".txt",
})

# Import/require útvonalakat felismerő regex (JS/TS/Python)
IMPORT_PATH_RE = re.compile(
    r"""(?:
        (?:import|export)\s[^'"]*['"]([^'"]+)['"]   # JS/TS: import ... from '...'
        |
        (?:require|import)\s*\(\s*['"]([^'"]+)['"]  # JS/TS: require('...') / import('...')
        |
        ^\s*(?:import|from)\s+(\S+)                 # Python: import x / from x import y
    )""",
    re.VERBOSE | re.MULTILINE,
)

DEFAULT_SKIP_DIRS: frozenset[str] = frozenset({
    # VCS
    ".git", ".hg", ".svn",
    # Python cache / tooling
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".dmypy",
    # Python virtual envs
    ".venv", "venv", "pvenv", ".pvenv", "env", ".env",
    "virtualenv", ".virtualenv",
    # JS/TS build tooling
    ".next", ".nuxt", ".svelte-kit", ".turbo", ".parcel-cache",
    # Build artefacts
    "dist", "build", "out", "coverage",
})

# Útvonal-alapú zajprofilhoz – ezek a könyvtárak TRUSTED_NOISE-nak számítanak,
# de nem kerülnek skip-elésre (bekerülnek a leletekbe, csak alacsonyabb súllyal).
PATH_NOISE_DIRS: frozenset[str] = frozenset({
    "tests", "test",
    "locale", "locales", "lang", "langs", "i18n", "l10n",
    "data", "fixtures", "samples", "testdata",
})

# Third-party könyvtárak – auditálandó idegen kód, nem megbízható zaj.
PATH_THIRD_PARTY_DIRS: frozenset[str] = frozenset({
    "node_modules",
    "site-packages", "dist-packages",
    "vendor", "vendors",
    "third_party", "third-party",
    "extern", "external",
})

IDENTIFIER_RE = re.compile(r"\b[A-Za-z_$\u0080-\uFFFF][A-Za-z0-9_$\u0080-\uFFFF]*\b")

# Script name detection based on Unicode character names
SCRIPT_KEYWORDS: tuple[tuple[str, str], ...] = (
    ("LATIN",    "LATIN"),
    ("CYRILLIC", "CYRILLIC"),
    ("GREEK",    "GREEK"),
    ("HEBREW",   "HEBREW"),
    ("ARABIC",   "ARABIC"),
    ("HIRAGANA", "EAST_ASIAN"),
    ("KATAKANA", "EAST_ASIAN"),
    ("HANGUL",   "EAST_ASIAN"),
    ("CJK",      "EAST_ASIAN"),
)

SNIPPET_MAX_LEN = 140


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    ALLOW = "ALLOW"
    INFO  = "INFO"   # háttérzaj, minifikált / dependency fájlok
    WARN  = "WARN"   # gyanús, felülvizsgálandó
    AUDIT = "AUDIT"  # third-party kódban talált, auditálandó idegen kód
    ERROR = "ERROR"  # blokkoló, saját kódban biztonsági kockázat


class FindingKind(str, Enum):
    CHAR   = "CHAR"
    IDENT  = "IDENT"
    IMPORT = "IMPORT"
    ERROR  = "ERROR"


class FileRiskProfile(str, Enum):
    """Kockázati profil – kiterjesztés és útvonal alapján kerül meghatározásra.

    EXECUTABLE    – végrehajtható forráskód (.js, .ts, .py stb.) – szigorú szabályok
    TRUSTED_NOISE – saját tesztadat, lokalizáció, dokumentáció – enyhébb szabályok
    THIRD_PARTY   – node_modules, site-packages, vendor stb. – auditálandó idegen kód
    NEUTRAL       – minden más
    """
    EXECUTABLE    = "executable"
    TRUSTED_NOISE = "trusted_noise"
    THIRD_PARTY   = "third_party"
    NEUTRAL       = "neutral"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    line: int
    col: int
    kind: FindingKind
    details: str
    snippet: str
    in_node_modules: bool
    is_minified_like: bool
    severity: Severity
    risk_profile: FileRiskProfile = FileRiskProfile.NEUTRAL


# ---------------------------------------------------------------------------
# Unicode helpers
# ---------------------------------------------------------------------------

def char_name(ch: str) -> str:
    return unicodedata.name(ch, "UNKNOWN")


def _is_path_noise_dir(path: Path) -> bool:
    """Igaz, ha az útvonal bármely komponense PATH_NOISE_DIRS-ben van."""
    return bool(path.parts and PATH_NOISE_DIRS.intersection(path.parts))


def _is_path_third_party(path: Path) -> bool:
    """Igaz, ha az útvonal bármely komponense PATH_THIRD_PARTY_DIRS-ben van."""
    return bool(path.parts and PATH_THIRD_PARTY_DIRS.intersection(path.parts))


def file_risk_profile(path: Path) -> FileRiskProfile:
    """Meghatározza a fájl kockázati profilját.

    Prioritási sorrend:
    1. Third-party könyvtár (node_modules/, site-packages/ stb.) → THIRD_PARTY
    2. Zajkönyvtár (tests/, locale/ stb.) → TRUSTED_NOISE
    3. Trusted noise kiterjesztés (.json, .yml, .md stb.) → TRUSTED_NOISE
    4. Executable kiterjesztés (.js, .ts, .py stb.) → EXECUTABLE
    5. Egyébként → NEUTRAL
    """
    if _is_path_third_party(path):
        return FileRiskProfile.THIRD_PARTY
    if _is_path_noise_dir(path):
        return FileRiskProfile.TRUSTED_NOISE
    ext = path.suffix.lower()
    if ext in TRUSTED_NOISE_EXTENSIONS:
        return FileRiskProfile.TRUSTED_NOISE
    if ext in EXECUTABLE_EXTENSIONS:
        return FileRiskProfile.EXECUTABLE
    return FileRiskProfile.NEUTRAL


def script_of_char(ch: str) -> str:
    """Return a coarse script name for *ch* based on its Unicode character name."""
    if ch in {"_", "$"} or ch.isdigit():
        return "COMMON"

    unicode_name = unicodedata.name(ch, "")
    if not unicode_name:
        return "UNKNOWN"

    for keyword, script in SCRIPT_KEYWORDS:
        if keyword in unicode_name:
            return script

    return "OTHER"


def _char_severity_by_profile(profile: FileRiskProfile) -> Severity:
    """BIDI/zero-width/Cf karakterek severity-je profilonként.

    EXECUTABLE  → ERROR  (Trojan Source közvetlen veszélye)
    THIRD_PARTY → AUDIT  (idegen kód, auditálandó, de nem blokkoló alapból)
    TRUSTED_NOISE → WARN (pl. RTL szöveg .md-ben, lokalizáció)
    NEUTRAL     → ERROR  (ismeretlen kontextus, óvatosság)
    """
    return {
        FileRiskProfile.EXECUTABLE:    Severity.ERROR,
        FileRiskProfile.THIRD_PARTY:   Severity.AUDIT,
        FileRiskProfile.TRUSTED_NOISE: Severity.WARN,
        FileRiskProfile.NEUTRAL:       Severity.ERROR,
    }[profile]


def classify_char(
    ch: str,
    *,
    in_node_modules: bool,
    is_minified_like: bool,
    risk_profile: FileRiskProfile = FileRiskProfile.NEUTRAL,
) -> tuple[bool, str, Severity]:
    """
    Return *(is_suspicious, details, severity)* for a single character.

    - EXECUTABLE / NEUTRAL: BIDI/zero-width → ERROR
    - THIRD_PARTY: BIDI/zero-width → AUDIT
    - TRUSTED_NOISE: BIDI/zero-width → WARN

    Returns ``(False, "", Severity.ALLOW)`` when the character is clean.
    """
    code     = ord(ch)
    category = unicodedata.category(ch)

    if code in BIDI_CONTROL_CODES:
        severity = _char_severity_by_profile(risk_profile)
        return True, f"BIDI_CONTROL {hex(code)} {char_name(ch)}", severity

    if code in ZERO_WIDTH_CODES:
        severity = _char_severity_by_profile(risk_profile)
        return True, f"ZERO_WIDTH {hex(code)} {char_name(ch)}", severity

    if category == "Cf":
        severity = _char_severity_by_profile(risk_profile)
        return True, f"Cf {hex(code)} {char_name(ch)}", severity

    if category == "Cc":
        if code in ALLOWED_CONTROL_CODES:
            return False, "", Severity.ALLOW
        severity = Severity.INFO if (in_node_modules or is_minified_like) else Severity.WARN
        return True, f"Cc {hex(code)} {char_name(ch)}", severity

    return False, "", Severity.ALLOW


def analyze_identifier(
    identifier: str,
    *,
    risk_profile: FileRiskProfile = FileRiskProfile.NEUTRAL,
) -> list[tuple[str, Severity]]:
    """
    Return a list of *(details, severity)* pairs for a suspicious identifier.

    NON_ASCII_IDENTIFIER mindig WARN – az összes profilban.
    MIXED_SCRIPT_IDENTIFIER mindig ERROR – azonosítóban script-keveredés egyértelműen gyanús.

    Returns an empty list when the identifier is clean (pure ASCII).
    """
    if all(ord(ch) < 128 for ch in identifier):
        return []

    non_ascii_severity = {
        FileRiskProfile.THIRD_PARTY:   Severity.AUDIT,
        FileRiskProfile.TRUSTED_NOISE: Severity.INFO,
    }.get(risk_profile, Severity.WARN)
    issues: list[tuple[str, Severity]] = [("NON_ASCII_IDENTIFIER", non_ascii_severity)]

    scripts = {
        script_of_char(ch)
        for ch in identifier
        if ch not in {"_", "$"} and not ch.isdigit()
    }
    scripts.discard("COMMON")

    if len(scripts) > 1:
        issues.append((
            f"MIXED_SCRIPT_IDENTIFIER {sorted(scripts)}",
            Severity.ERROR,
        ))

    return issues


# ---------------------------------------------------------------------------
# File utilities
# ---------------------------------------------------------------------------

def safe_snippet(line: str, max_len: int = SNIPPET_MAX_LEN) -> str:
    line = line.rstrip("\n")
    return line if len(line) <= max_len else line[: max_len - 3] + "..."


def looks_minified(path: str, line: str) -> bool:
    if ".min." in Path(path).name.lower():
        return True
    stripped = line.strip()
    return len(stripped) > 500 and stripped.count(" ") < max(10, len(stripped) // 40)


def should_scan_file(path: Path) -> bool:
    return path.suffix.lower() in SOURCE_EXTENSIONS


def iter_files(root: str, *, include_node_modules: bool) -> Iterator[Path]:
    skip_dirs = set(DEFAULT_SKIP_DIRS)
    if not include_node_modules:
        skip_dirs.add("node_modules")

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for filename in filenames:
            path = Path(dirpath) / filename
            if should_scan_file(path):
                yield path


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

def _is_in_node_modules(path: Path) -> bool:
    return "node_modules" in path.parts


def _scan_import_paths(
    findings: list[Finding],
    path: str,
    lineno: int,
    line: str,
    snippet: str,
    *,
    in_node_modules: bool,
    is_minified_like: bool,
    risk_profile: FileRiskProfile,
) -> None:
    """Import/require útvonalakban gyanús Unicode karaktereket keres."""
    if risk_profile not in {FileRiskProfile.EXECUTABLE, FileRiskProfile.THIRD_PARTY}:
        return

    for match in IMPORT_PATH_RE.finditer(line):
        import_path = next(g for g in match.groups() if g is not None)
        for colno, ch in enumerate(import_path, match.start() + 1):
            suspicious, details, _ = classify_char(
                ch,
                in_node_modules=in_node_modules,
                is_minified_like=is_minified_like,
                risk_profile=risk_profile,
            )
            if suspicious:
                findings.append(Finding(
                    path=path, line=lineno, col=colno,
                    kind=FindingKind.IMPORT,
                    details=f"IMPORT_PATH {details}",
                    snippet=snippet,
                    in_node_modules=in_node_modules,
                    is_minified_like=is_minified_like,
                    severity=Severity.ERROR,  # import útvonalon mindig ERROR
                    risk_profile=risk_profile,
                ))


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file and return all findings."""
    findings: list[Finding] = []
    in_node_modules = _is_in_node_modules(path)
    profile = file_risk_profile(path)

    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                is_minified_like = looks_minified(str(path), line)
                snippet = safe_snippet(line)

                _scan_chars(
                    findings, str(path), lineno, line, snippet,
                    in_node_modules=in_node_modules,
                    is_minified_like=is_minified_like,
                    risk_profile=profile,
                )
                _scan_identifiers(
                    findings, str(path), lineno, line, snippet,
                    in_node_modules=in_node_modules,
                    is_minified_like=is_minified_like,
                    risk_profile=profile,
                )
                _scan_import_paths(
                    findings, str(path), lineno, line, snippet,
                    in_node_modules=in_node_modules,
                    is_minified_like=is_minified_like,
                    risk_profile=profile,
                )

    except Exception as exc:
        findings.append(Finding(
            path=str(path), line=0, col=0,
            kind=FindingKind.ERROR,
            details=f"Could not scan file: {exc}",
            snippet="",
            in_node_modules=in_node_modules,
            is_minified_like=False,
            severity=Severity.ERROR,
            risk_profile=profile,
        ))

    return findings


def _scan_chars(
    findings: list[Finding],
    path: str,
    lineno: int,
    line: str,
    snippet: str,
    *,
    in_node_modules: bool,
    is_minified_like: bool,
    risk_profile: FileRiskProfile = FileRiskProfile.NEUTRAL,
) -> None:
    for colno, ch in enumerate(line, 1):
        suspicious, details, severity = classify_char(
            ch,
            in_node_modules=in_node_modules,
            is_minified_like=is_minified_like,
            risk_profile=risk_profile,
        )
        if suspicious:
            findings.append(Finding(
                path=path, line=lineno, col=colno,
                kind=FindingKind.CHAR,
                details=details, snippet=snippet,
                in_node_modules=in_node_modules,
                is_minified_like=is_minified_like,
                severity=severity,
                risk_profile=risk_profile,
            ))


def _scan_identifiers(
    findings: list[Finding],
    path: str,
    lineno: int,
    line: str,
    snippet: str,
    *,
    in_node_modules: bool,
    is_minified_like: bool,
    risk_profile: FileRiskProfile = FileRiskProfile.NEUTRAL,
) -> None:
    for match in IDENTIFIER_RE.finditer(line):
        for details, severity in analyze_identifier(match.group(0), risk_profile=risk_profile):
            findings.append(Finding(
                path=path, line=lineno, col=match.start() + 1,
                kind=FindingKind.IDENT,
                details=f"{details}: {match.group(0)!r}",
                snippet=snippet,
                in_node_modules=in_node_modules,
                is_minified_like=is_minified_like,
                severity=severity,
                risk_profile=risk_profile,
            ))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def _flags(item: Finding) -> str:
    flags = []
    if item.risk_profile is not FileRiskProfile.NEUTRAL:
        flags.append(item.risk_profile.value)
    if item.is_minified_like:
        flags.append("minified-like")
    return f" [{', '.join(flags)}]" if flags else ""


def finding_to_dict(item: Finding) -> dict:
    """Finding → JSON-serializable dict."""
    return {
        "path":            item.path,
        "line":            item.line,
        "col":             item.col,
        "kind":            item.kind.value,
        "severity":        item.severity.value,
        "risk_profile":    item.risk_profile.value,
        "details":         item.details,
        "snippet":         item.snippet,
        "is_minified_like": item.is_minified_like,
    }


def _build_summary_dict(findings: list[Finding]) -> dict:
    severity_counts: Counter[str] = Counter(item.severity.value for item in findings)
    kind_counts:     Counter[str] = Counter(item.kind.value     for item in findings)
    profile_counts:  Counter[str] = Counter(item.risk_profile.value for item in findings)
    third_party_count = sum(
        1 for item in findings if item.risk_profile is FileRiskProfile.THIRD_PARTY
    )
    return {
        "total":          len(findings),
        "by_severity":    dict(severity_counts),
        "by_kind":        dict(kind_counts),
        "by_risk_profile": dict(profile_counts),
        "project_files":  len(findings) - third_party_count,
        "third_party":    third_party_count,
        "minified_like":  sum(1 for item in findings if item.is_minified_like),
    }


def output_json(
    findings: list[Finding],
    *,
    root: str,
    include_node_modules: bool,
    blocked: bool,
    files_scanned: int,
) -> None:
    """Teljes eredményt JSON-ként ír stdout-ra."""
    payload = {
        "scanned":              str(Path(root).resolve()),
        "include_node_modules": include_node_modules,
        "files_scanned":        files_scanned,
        "blocked":              blocked,
        "summary":              _build_summary_dict(findings),
        "findings":             [finding_to_dict(f) for f in findings],
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2))


def print_findings(findings: list[Finding]) -> None:
    for item in findings:
        location = f"{item.path}:{item.line}:{item.col}"
        print(
            f"{location}  [{item.severity.value}] [{item.kind.value}] "
            f"{item.details}{_flags(item)}"
        )
        if item.snippet:
            print(f"    {item.snippet}")


def print_summary(findings: list[Finding]) -> None:
    s = _build_summary_dict(findings)
    print("Summary:")
    for key in sorted(s["by_severity"]):
        print(f"  {key}: {s['by_severity'][key]}")
    for key in sorted(s["by_kind"]):
        print(f"  {key}: {s['by_kind'][key]}")
    for key in sorted(s["by_risk_profile"]):
        print(f"  profile:{key}: {s['by_risk_profile'][key]}")
    print(f"  project_files: {s['project_files']}")
    print(f"  third_party:   {s['third_party']}")
    print(f"  minified_like: {s['minified_like']}")
    print(f"  TOTAL: {s['total']}")


# ---------------------------------------------------------------------------
# Exit-code logic
# ---------------------------------------------------------------------------

def should_fail(findings: list[Finding], fail_on: str) -> bool:
    """Meghatározza, hogy a leletek alapján a folyamat sikertelennek számít-e.

    AUDIT severity alapból nem blokkoló – a third-party kód auditálása
    szándékosan különül el a saját kód ellenőrzésétől.
    """
    errors = [item for item in findings if item.severity is Severity.ERROR]
    if not errors:
        return False
    if fail_on == "project-only":
        return any(
            item.risk_profile not in (FileRiskProfile.THIRD_PARTY,)
            for item in errors
        )
    return True  # "any"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan source files for suspicious Unicode characters and mixed-script identifiers."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Root directory to scan (default: current directory).",
    )
    parser.add_argument(
        "--include-node-modules",
        action="store_true",
        help="Also scan files under node_modules.",
    )
    parser.add_argument(
        "--fail-on",
        choices=["any", "project-only"],
        default="any",
        help=(
            "Exit with non-zero on any ERROR finding, or only when ERROR findings exist "
            "outside node_modules. Default: any"
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of human-readable text.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root

    paths = list(iter_files(root, include_node_modules=args.include_node_modules))
    max_workers = min(16, (os.cpu_count() or 1) * 2)

    all_findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for findings in executor.map(scan_file, paths):
            all_findings.extend(findings)

    all_findings.sort(key=lambda f: (f.path, f.line, f.col))

    blocked = should_fail(all_findings, args.fail_on)

    if args.json:
        output_json(
            all_findings,
            root=root,
            include_node_modules=args.include_node_modules,
            blocked=blocked,
            files_scanned=len(paths),
        )
        return 1 if blocked else 0

    print(f"Scanned: {Path(root).resolve()}")
    print(f"Include node_modules: {'yes' if args.include_node_modules else 'no'}")
    print(f"Files scanned: {len(paths)}")
    print(f"Workers: {max_workers}")
    print()

    if not all_findings:
        print("OK: no suspicious Unicode issues found.")
        return 0

    print_findings(all_findings)
    print()
    print_summary(all_findings)

    return 1 if blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
