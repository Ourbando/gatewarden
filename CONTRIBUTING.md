# Contributing

The best contribution to a gate is a way past it. If you can make an action slip through a policy
that should stop it, that is a bug and a gift, and the fix is usually one line.

## Report a bypass

Open an issue with the action, the policy in force, and the expected versus the actual verdict.
Better still, add the failing case to the adversary so the signed proof turns red until it is fixed.

## Add an attack

Every attack is one line in `railward/adversary.py`:

```python
{"name": "bash-your-attack", "request": {"action": "bash", "command": "..."}},
```

Then:

```
make attack   # runs the adversary and writes a signed proof
make verify   # recomputes the chain and checks the signature
```

Under `examples/safe.yaml` every attack must be blocked (`0 leaked`). If yours leaks, that is a
real finding: open a PR with the attack and, if you have one, the policy or engine fix.

## Develop

```
pip install -e ".[dev]"
make test     # the unit suite
make gate     # publish gate: no leaks, no secrets, no em-dashes
```

Run `railward lint --policy your.yaml` to prove a policy loads and has no dead deny rule.

## Principles (please keep them)

- Fail-closed. Anything a policy does not explicitly allow is refused; any error resolves to `ask`,
  never `allow`, and the hook never crashes.
- Veto-only. The hook emits `deny` or `ask`, never `allow`. It can tighten permissions, never widen.
- The decision function is pure: no I/O, no clock, no model. Keep it that way.
- The proof stays green. A change that alters behavior updates the tests and the adversary so the
  signed proof still verifies.

## AI-assisted contributions

Welcome, on one condition: you understand and can explain every line you submit. That is the whole
point of the tool. By contributing you agree your work is MIT-licensed, the same as the project.
