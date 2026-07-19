"""explain, ctf, and the reaction art. Cosmetic surfaces still get contracts: deterministic,
pipe-safe, and honest about the underlying decision."""
from __future__ import annotations

from railward import art
from railward.cli import main


def test_react_deny_is_deterministic_and_plain() -> None:
    a = art.react("deny", "destructive command", color=False)
    b = art.react("deny", "destructive command", color=False)
    assert a == b                     # no RNG
    assert "\033" not in a            # pipe-safe when color is off
    assert "DENIED" in a


def test_react_ask_and_allow() -> None:
    assert "ASK A HUMAN" in art.react("ask", "needs review", color=False)
    assert art.react("allow", "fine", color=False) == ""   # nothing on a pass


def test_portcullis_counts_are_real() -> None:
    clean = art.portcullis(41, 0, color=False)
    holed = art.portcullis(41, 12, color=False)
    assert "41/41 held" in clean
    assert clean.count("│") == 41 and "╳" not in clean
    assert "29/41 held" in holed
    assert holed.count("╳") == 12


def test_explain_traces_the_pipe_bypass(capsys) -> None:
    rc = main(["explain", "--policy", "examples/strict.yaml", "--command", "echo hi | sh"])
    out = capsys.readouterr().out
    assert rc == 1                    # denied
    assert "verdict: deny" in out
    assert "sub-command: sh" in out   # the offending part is named


def test_explain_allows_a_clean_command(capsys) -> None:
    rc = main(["explain", "--policy", "examples/strict.yaml", "--command", "git log | cat"])
    assert rc == 0
    assert "verdict: allow" in capsys.readouterr().out


def test_ctf_hit_and_miss(capsys) -> None:
    assert main(["ctf", "--guess", "bash-rm-root"]) == 0      # rm leaks through the holed policy
    assert "HIT" in capsys.readouterr().out
    assert main(["ctf", "--guess", "bash-mkfs-disk"]) == 1    # mkfs is still blocked
    assert "MISS" in capsys.readouterr().out


def test_ctf_unknown_guess(capsys) -> None:
    assert main(["ctf", "--guess", "no-such-attack"]) == 2
    assert "no attack named" in capsys.readouterr().out
