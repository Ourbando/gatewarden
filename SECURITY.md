# Security model

`railward` reduces risk. It does not eliminate it. Read this before relying on it.

## What it defends

- It decides every action an agent proposes through a supported surface (the Claude Code
  PreToolUse hook, the `check` CLI, or the `decide` API) and refuses anything a policy does not
  explicitly allow. The default is fail-closed.
- Command matching resists common evasions: case (`RM`), absolute paths (`/bin/rm`), extra
  whitespace, flag reordering, and chained injection (`;`, `&&`, `|`) are all normalized before a
  policy pattern is applied.
- Path scoping canonicalizes `.` and `..` before globbing, so a relative path cannot escape its
  intended scope by walking upward.
- Every decision can be written to a hash-chained, Ed25519-signed log. Editing any earlier record
  breaks every hash after it, and the signature is checked against a pinned public key, never one
  carried inside the log.
- The hook is veto-only: it emits only `deny` or `ask`, never `allow`. It can tighten the harness's
  permissions but never widen them, so a policy bug can only over-restrict, never wave something
  through.
- The hook is fail-closed on its own faults, not just on the agent's actions. A configured policy
  that will not load, unparseable input, or an internal error resolves to `ask`. It never crashes
  (a crashing hook a harness would treat as a non-blocking error is itself a fail-open), and the
  signed proof carries a fail-open probe battery that attests this.

## What it does NOT defend

- It only sees actions routed through it. A process already handed a raw shell, or a tool that
  bypasses the hook, is outside its control.
- Path scoping does not resolve symlinks. A symlink with an innocent name that points at a
  sensitive location will not be caught by name-based globbing. Resolve or forbid symlinks in your
  own environment if that matters.
- Policy regexes are supplied by you and are trusted. A pathological pattern is your own risk;
  keep patterns simple. Command input is length-bounded to limit matching cost.
- It does not sandbox, rate-limit, or inspect the content an allowed action reads or writes.
- An allow rule that matches by a loose prefix can be a bypass vector: if a command matches an
  allow rule but chains a dangerous part that no deny rule catches, it is permitted. Prefer deny
  rules for what must never run, and keep allow-lists tight. The bundled `examples/safe.yaml` is a
  labelled toy, not a finished policy.

## Dependencies

The runtime surface is deliberately two well-known libraries: `cryptography` (the Ed25519
signature and verification) and `PyYAML` (parsing policy files). Both are pinned with a floor in
`pyproject.toml`. The gate, the decision function, and the log format use only the standard library.

## Reporting

Open an issue for anything that looks like a bypass, ideally with a failing case for the adversary
in `railward/adversary.py`. A good bug report is a new attack.

## No warranty

This is MIT-licensed software provided as is, with no warranty. It is a reference control layer,
not a certified product.
