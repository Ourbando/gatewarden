# Changelog

This project treats its own history as an adversary log: each release names the class of bypass or
fail-open the gate now closes, and every closure is attested by a test and by the signed proof. The
number of blocked attacks only goes up.

## 0.3.0

Coverage upgrade. The gate stopped relying on the fail-closed default to catch dangerous classes
nobody had named, and started naming them. Measured against the 287-class threat taxonomy on
`examples/strict.yaml`, coverage moved from **102 deny-rule / 143 default-only / 42 leak** to
**284 deny-rule / 1 default-only / 2 leak**. The adversary battery grew from 41 attacks to 117, and
the signed proof now attests `examples/strict.yaml`, the production-shaped policy people actually
deploy, rather than the toy example.

New capability:

- **Agent poisoning is refused (OWASP ASI06 / LLM01).** Writes to the files that reprogram the
  agent, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.mcp.json`, `.github/copilot-instructions.md`
  and agent memory stores, are denied. Nothing executes when they are written, the diff reads as
  documentation, and every future session in that repo runs with the attacker's instructions.
- **Gate self-tampering is refused (ASI10 / T1562.001).** The policy, the decision core, the hook
  adapter, the signed proof, the signing keys, and the runtime's hook settings are off limits, as
  is unsetting the gate's own environment variable. A gate an agent can edit is a suggestion.
- **Supply-chain writes are refused (T1195.001 / T1546).** CI workflows, `Dockerfile`, `Makefile`,
  `setup.py`, pre-commit config, `.git/hooks/`, `.gitattributes` and editor task files. None of
  them execute on write; all of them execute on the next build, commit, or editor task.
- **Read commands no longer bypass path rules.** File arguments of known readers (`cat`, `head`,
  `grep`, and the rest) are extracted and checked as reads, so `cat /etc/shadow` meets the same
  rules as `read /etc/shadow`. The search pattern of a `grep`-like command is deliberately skipped,
  so `grep secret-notes README` is not denied on its search term.
- **Credential paths match relative and absolute form.** Fixes a real leak: `/home/u/.aws/credentials`
  was refused while a bare `.aws/credentials` was allowed as an ordinary workspace read, so the
  protection depended on how the path happened to be spelled.
- **Platform parity.** macOS (`spctl`, `csrutil`, `tccutil`, `tmutil`, keychain reads) and Windows
  (`powershell -enc`, `reg add` Run keys, `schtasks`, `vssadmin`, `wevtutil`, Defender controls) are
  named classes rather than default-only. The gate is no longer Linux-shaped.
- **Interpreter inline code is recursed, with the ceiling stated.** The program string passed to
  `python -c` / `node -e` / `sh -c` is pushed back through the gate, so anything it names is denied.
  What names nothing resolves to `ask`, never `allow`: token matching cannot read intent, and
  THREAT_MODEL.md says so plainly instead of implying otherwise.
- **A stable integration API.** `railward.Gate` is the contract for adapters: veto-only, pure,
  fail-closed, with `ask` explicitly not `allow`. Recipe in `docs/ADAPTERS.md`.
- **Coverage is measurable and cannot drift.** `railward coverage` measures a policy against the
  taxonomy; the doc's verdict column is regenerated from live measurement, and a test fails if the
  document and the gate disagree.

Policy language: path globs gained `{a,b}` alternation and a `**/` prefix meaning "at any depth,
including none". Both are pure and bounded at load, and `railward lint` reports an allow rule that
uses the widening prefix, since broadening a deny is the point but broadening an allow is a hole.

Two defects found and fixed:

- **Stale reference proof.** The committed proof attested an older, smaller battery. Regenerated
  under the same published key, and a test now fails if it falls behind the battery again.
- **Relative secret reads leaked.** Closed by the credential path rules above, pinned by the
  `readcmd-relative-aws-creds` attack.

Two classes are knowingly **not** covered, and are named in THREAT_MODEL.md rather than rounded
off: neutering a test so it always passes, and reading an untrusted document that steers later tool
calls. Both are semantic. Closing them would mean claiming to understand content.

## 0.2.0

First public release as railward: a fail-closed, veto-only decision core; a self-attacking
adversary; a signed, re-runnable proof; policy lint; and Claude Code plugin packaging. The name
settles here; the gate, adversary, and proof are the same core attested below.

Attack and fail-open classes closed, each with the evidence that keeps it closed:

- **Allow-by-default and default fail-open.** The default is fail-closed; `default: allow` is
  rejected at load. (`tests/test_policy.py`, `tests/test_fuzz.py`)
- **Fail-open by policy typo.** An invalid rule regex is a loud load error, never a silently dropped
  deny. (`tests/test_policy_validation.py`)
- **Evasion by case, path, whitespace, and injection.** argv[0] basename, command tokenization, path
  canonicalization. (`tests/test_decide.py`)
- **Fail-open on bad input.** Non-mapping, missing action, oversized, unparseable, and non-UTF-8
  input resolve to a blocking decision. (`railward/robustness.py`, `tests/test_hook_failclosed.py`)
- **Compound-command smuggling.** A shell command is decomposed into pipe/`;`/`&&` segments and
  command-substitution bodies; an anchored allow can no longer wave a payload through a pipe.
  (`tests/test_compound.py`)
- **Redirection reads and process substitution.** Input redirection (`< secrets`) is checked as a
  read; process substitution (`<(cmd)`) is executed and evaluated. (`tests/test_redirection.py`)
- **ReDoS by policy regex.** A command regex that can catastrophically backtrack is rejected at
  load, so a crafted command cannot hang the gate. (`tests/test_policy_validation.py`)

Tooling that keeps the above honest:

- **Property fuzzing** over thousands of generated policies: allow is only ever produced by a
  matched allow-rule, and the gate never crashes. (`tests/test_fuzz.py`)
- **Purity proof**: the decision core is statically checked to reach no I/O, clock, or randomness.
  (`tests/test_purity.py`)
- **Mutation gate**: hand-picked mutations that remove a protection must each turn the suite red, so
  the tests are proven to have teeth. (`scripts/mutation_check.py`)
