#!/usr/bin/env bash
# Fail-closed publish gate. Refuses to ship if a private/moat marker, a secret, or an em-dash
# appears anywhere in the tree. Deliberately over-broad: a false positive means a human looks,
# which is the safe direction. Run before every publish; it is also wired into CI.
set -uo pipefail
self="$(basename "$0")"

# Publisher-specific markers (names, codenames, project terms) live OUTSIDE the tree in an
# untracked file, one extended-regex per line, so this script never contains the bytes it
# screens for.
secret='BEGIN OPENSSH PRIVATE|-----BEGIN [A-Z ]*PRIVATE KEY|ghp_[A-Za-z0-9]|xox[abpr]-|/Use''rs/'
patterns="$secret"
extra_file="${RAILWARD_PUBLISH_PATTERNS:-$HOME/.config/railward/publish_patterns}"
if [ -f "$extra_file" ]; then
  extra=$(grep -Ev '^[[:space:]]*(#|$)' "$extra_file" | paste -sd'|' -)
  [ -n "$extra" ] && patterns="$patterns|$extra"
fi
dashes=$'\xe2\x80\x94|\xe2\x80\x93'
fail=0

hits=$(grep -RIlniE "$patterns" --exclude="$self" --exclude-dir=.git --exclude-dir=.venv --exclude-dir=keys . || true)
if [ -n "$hits" ]; then echo "PUBLISH GATE: forbidden marker in:" >&2; echo "$hits" >&2; fail=1; fi

edash=$(grep -RIlE "$dashes" --exclude="$self" --exclude-dir=.git --exclude-dir=.venv --exclude-dir=keys . || true)
if [ -n "$edash" ]; then echo "PUBLISH GATE: em/en dash in:" >&2; echo "$edash" >&2; fail=1; fi

badpem=$(git ls-files 2>/dev/null | grep -E '\.pem$' | grep -v '^examples/pubkey\.pem$' || true)
if [ -n "$badpem" ]; then echo "PUBLISH GATE: a non-public .pem is tracked: $badpem" >&2; fail=1; fi

if [ "$fail" -eq 0 ]; then echo "publish gate: clean"; fi
exit "$fail"
