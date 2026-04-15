# Claude Code Skill Scanner Hook

A security hook for Claude Code that automatically scans downloaded skills for prompt injection before they enter your active skills directory.

## The Problem

Skills downloaded from public repositories can contain hidden prompt injection payloads. When Claude Code reads a compromised skill file, it may interpret embedded instructions as legitimate commands — giving malicious code access to your session.

Prompt injection is ranked **#1 in OWASP's Top 10 for LLM Applications**. A [2026 academic study](https://arxiv.org/abs/2603.21642) tested 7 major AI development tools (including Claude Code, Cursor, and Gemini CLI) and found significant security gaps in most of them.

## How It Works

```
Download skill → staging/ → Hook triggers scan → Clean? → .claude/skills/
                                                → Suspicious? → BLOCK + alert
```

1. You place new skills in `staging/` — never directly into the active skills directory
2. A `PreToolUse` hook fires before every Claude Code action
3. `skill_scanner.py` scans for suspicious patterns: injection phrases, hidden shell commands, obfuscated instructions
4. If threats are found → Claude stops and displays the findings
5. If clean → the file moves automatically to `.claude/skills/`

## Setup

### 1. Clone the repository into your project

```bash
git clone https://github.com/GuyEliasaf/claude-code-skill-scanner.git 
```

Or copy the `.claude/` folder into your project root.

### 2. Create the staging directory

```bash
mkdir staging
```

### 3. Verify the hook is registered

Open Claude Code and run `/hooks` — you should see the PreToolUse hook listed.

> **Note:** On Windows, open `.claude/settings.json` and change `python3` to `python` in the command field if needed.

### 4. Configure paths (optional)

By default, the scanner looks for files in `./staging/` and moves clean files to `.claude/skills/`. You can change these paths by setting environment variables:

- `SKILL_STAGING_DIR` — where new skills are placed for review
- `SKILL_TARGET_DIR` — where clean skills are moved to
- `SKILL_SCAN_LOG` — path to the scan log file

## Exit Code Behavior

Claude Code hooks use exit codes to communicate decisions:

| Exit Code | Meaning |
|---|---|
| `0` | All clear — Claude continues normally |
| `2` | **Block** — Claude stops and receives the error from stderr as feedback |
| `1` | Warning only — Claude sees a warning but continues (does NOT block) |

The scanner outputs findings to `stderr` so Claude can read them and explain to the user what was blocked and why.

## What It Detects

| Pattern | Example |
|---|---|
| Instruction override | `ignore previous instructions`, `disregard all prior rules` |
| Hidden shell commands | `os.system(...)`, `subprocess.run(...)`, `eval(...)` |
| Obfuscated payloads | Base64-encoded commands, zero-width characters |
| Tag injection | Closing/opening XML-style tags to break prompt structure |
| Exfiltration attempts | `curl`, `wget`, `requests.post` to external URLs |
| Suspicious file access | Reading `.ssh`, `.aws`, `.env` or deleting files |

## Testing

Copy the example files to `staging/` and run the scanner:

```bash
# Test with a malicious skill (should block)
cp examples/malicious_skill.md staging/
python .claude/hooks/skill_scanner.py
# Expected: 🚨 findings + exit code 2

# Test with a clean skill (should pass)
cp examples/clean_skill.md staging/
python .claude/hooks/skill_scanner.py
# Expected: ✅ moved to .claude/skills/
```

To test inside Claude Code, place a file in `staging/` and ask Claude to perform any action. The hook will fire and block if threats are found.

## Limitations

- This scanner uses pattern matching — it catches common injection techniques but is not a substitute for manually reviewing skills from untrusted sources. Sophisticated attacks may use obfuscation methods not covered by these patterns.
- The hook scans on every tool action, but files added to `staging/` mid-session will only be caught on the **next** tool call, not retroactively.
- The hook runs on every Claude Code action (matched by `.*`). For large staging directories this may add latency. Keep staging clean by removing reviewed files.

## References

- [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Are AI-assisted Development Tools Immune to Prompt Injection? (2026)](https://arxiv.org/abs/2603.21642)
- [Prompt Injection Attacks on Agentic Coding Assistants (2026)](https://arxiv.org/abs/2601.17548)

## License

MIT
