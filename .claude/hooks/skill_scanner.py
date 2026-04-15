#!/usr/bin/env python3
"""
Claude Code Hook: Skill Scanner
Scans files in the staging directory for prompt injection patterns
before allowing them into the active skills directory.

Usage: Configured as a PreToolUse hook in .claude/settings.json
"""

import os
import re
import sys
import shutil
import base64
import json
from pathlib import Path
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────────────────────

STAGING_DIR = os.environ.get("SKILL_STAGING_DIR", "./staging")
SKILLS_DIR = os.environ.get("SKILL_TARGET_DIR", ".claude/skills")
LOG_FILE = os.environ.get("SKILL_SCAN_LOG", ".claude/hooks/scan.log")

# ─── Detection Patterns ──────────────────────────────────────────────────────

# Direct instruction override attempts
INJECTION_PHRASES = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?(prior|previous|above)\s+(rules|instructions|guidelines)",
    r"forget\s+(everything|all)\s+(above|before|previously)",
    r"you\s+are\s+now\s+in\s+(developer|debug|admin|god)\s+mode",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*you\s+are",
    r"<\s*/?\s*system\s*>",
    r"<\s*/?\s*instructions?\s*>",
    r"BEGIN\s+OVERRIDE",
    r"EXECUTE\s+IMMEDIATELY",
    r"do\s+anything\s+now",
    r"jailbreak",
    r"DAN\s+mode",
]

# Shell/code execution patterns
EXEC_PATTERNS = [
    r"os\.system\s*\(",
    r"subprocess\.(run|call|Popen|check_output)\s*\(",
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__\s*\(",
    r"compile\s*\(",
    r"execfile\s*\(",
    r"pty\.spawn\s*\(",
    r"ctypes\.",
]

# Exfiltration / network access
EXFIL_PATTERNS = [
    r"curl\s+",
    r"wget\s+",
    r"requests\.(get|post|put|delete)\s*\(",
    r"urllib\.request",
    r"httpx\.(get|post|put|delete|AsyncClient)\s*\(",
    r"fetch\s*\(",
    r"XMLHttpRequest",
    r"socket\.connect",
]

# Suspicious file operations
FILE_PATTERNS = [
    r"open\s*\(\s*['\"](/etc/|/root/|~\/\.ssh|~\/\.aws|~\/\.env)",
    r"shutil\.rmtree\s*\(",
    r"os\.remove\s*\(",
    r"os\.unlink\s*\(",
    r"pathlib.*\.unlink\s*\(",
]

# ─── Scanner ─────────────────────────────────────────────────────────────────


class ScanResult:
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[dict] = []

    def add_finding(self, severity: str, category: str, detail: str, line_num: int = 0):
        self.findings.append({
            "severity": severity,
            "category": category,
            "detail": detail,
            "line": line_num,
        })

    @property
    def is_clean(self) -> bool:
        return not any(f["severity"] in ("CRITICAL", "HIGH") for f in self.findings)

    def summary(self) -> str:
        if not self.findings:
            return f"✅ {self.filename}: Clean"
        lines = [f"🚨 {self.filename}: {len(self.findings)} issue(s) found"]
        for f in self.findings:
            loc = f" (line {f['line']})" if f["line"] else ""
            lines.append(f"  [{f['severity']}] {f['category']}{loc}: {f['detail']}")
        return "\n".join(lines)


def check_patterns(content: str, patterns: list[str], category: str, severity: str, result: ScanResult):
    """Check content against a list of regex patterns."""
    for pattern in patterns:
        for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
            line_num = content[:match.start()].count("\n") + 1
            snippet = match.group(0)[:80]
            result.add_finding(severity, category, snippet, line_num)


def check_base64_payloads(content: str, result: ScanResult):
    """Detect base64-encoded strings that decode to suspicious content."""
    b64_pattern = r"[A-Za-z0-9+/]{40,}={0,2}"
    for match in re.finditer(b64_pattern, content):
        try:
            decoded = base64.b64decode(match.group(0)).decode("utf-8", errors="ignore")
            # Check if decoded content contains suspicious patterns
            for pattern in INJECTION_PHRASES + EXEC_PATTERNS:
                if re.search(pattern, decoded, re.IGNORECASE):
                    line_num = content[:match.start()].count("\n") + 1
                    result.add_finding(
                        "CRITICAL",
                        "Obfuscated payload",
                        f"Base64 decodes to suspicious content: {decoded[:60]}...",
                        line_num,
                    )
                    break
        except Exception:
            pass


def check_zero_width_chars(content: str, result: ScanResult):
    """Detect zero-width characters that may hide instructions."""
    zw_pattern = r"[\u200b\u200c\u200d\u2060\ufeff]"
    matches = list(re.finditer(zw_pattern, content))
    if len(matches) > 3:
        line_num = content[:matches[0].start()].count("\n") + 1
        result.add_finding(
            "HIGH",
            "Hidden content",
            f"Found {len(matches)} zero-width characters (possible hidden instructions)",
            line_num,
        )


def scan_file(filepath: str) -> ScanResult:
    """Run all checks on a single file."""
    result = ScanResult(os.path.basename(filepath))

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        result.add_finding("HIGH", "Read error", str(e))
        return result

    # Run all pattern checks
    check_patterns(content, INJECTION_PHRASES, "Prompt injection", "CRITICAL", result)
    check_patterns(content, EXEC_PATTERNS, "Code execution", "HIGH", result)
    check_patterns(content, EXFIL_PATTERNS, "Exfiltration", "HIGH", result)
    check_patterns(content, FILE_PATTERNS, "Suspicious file access", "MEDIUM", result)

    # Obfuscation checks
    check_base64_payloads(content, result)
    check_zero_width_chars(content, result)

    return result


# ─── Hook Entry Point ────────────────────────────────────────────────────────


def log_result(result: ScanResult):
    """Append scan result to log file."""
    log_dir = os.path.dirname(LOG_FILE)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        timestamp = datetime.now().isoformat()
        f.write(f"[{timestamp}] {result.summary()}\n")


def main():
    # Consume stdin (Claude Code sends JSON hook data)
    try:
        sys.stdin.read()
    except Exception:
        pass

    staging = Path(STAGING_DIR)
    skills = Path(SKILLS_DIR)

    # If staging dir doesn't exist or is empty, nothing to do
    if not staging.exists():
        sys.exit(0)

    files = [f for f in staging.iterdir() if f.is_file()]
    if not files:
        sys.exit(0)

    # Ensure skills directory exists
    skills.mkdir(parents=True, exist_ok=True)

    blocked = False

    for filepath in files:
        result = scan_file(str(filepath))
        log_result(result)

        if result.is_clean:
            # Move to active skills directory
            dest = skills / filepath.name
            shutil.move(str(filepath), str(dest))
            print(f"✅ {filepath.name} → moved to skills/")
        else:
            # Keep in staging and alert
            print(result.summary(), file=sys.stderr)
            blocked = True

    if blocked:
        print("\n⛔ Scan blocked one or more files. Review them in staging/ before proceeding.", file=sys.stderr)
        sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
