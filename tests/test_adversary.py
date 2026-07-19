from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from railward import adversary, load_policy
from railward import log as plog


def test_safe_policy_blocks_every_attack():
    results = adversary.run_attacks(load_policy("examples/safe.yaml"))
    leaked = [r["attack"] for r in results if r["leaked"]]
    assert leaked == [], f"unexpected leaks: {leaked}"
    assert all(r["verdict"] == "deny" for r in results)


def test_holed_policy_leaks():
    results = adversary.run_attacks(load_policy("examples/holey.yaml"))
    assert any(r["leaked"] for r in results)


def test_proof_verifies_and_is_deterministic():
    key = Ed25519PrivateKey.generate()
    policy = load_policy("examples/safe.yaml")
    p1 = adversary.build_proof(policy, key)
    p2 = adversary.build_proof(policy, key)
    assert p1["head"] == p2["head"]        # same attacks + probes -> same chain
    assert p1["leaked"] == 0
    assert p1["robustness_failed_open"] == 0
    ok, _ = plog.verify_chain(p1["chain"], p1["sig"], key.public_key())
    assert ok


def test_holed_proof_reports_leaks():
    key = Ed25519PrivateKey.generate()
    proof = adversary.build_proof(load_policy("examples/holey.yaml"), key)
    assert proof["leaked"] > 0
