# Changelog

This project treats its own history as an adversary log: each release names the class of bypass or
fail-open the gate now closes, and every closure is attested by a test and by the signed proof. The
number of blocked attacks only goes up.

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
