"""The fail-open probe battery must find zero fail-opens, and the proof must attest it."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from railward import adversary, load_policy, robustness


def test_probes_find_no_fail_open():
    results = robustness.run_probes()
    assert results, "the battery must not be empty"
    opened = [r["probe"] for r in results if r["failed_open"]]
    assert opened == [], f"hook failed open on: {opened}"


def test_broken_and_unparseable_block_unconfigured_silent():
    by_name = {r["probe"]: r for r in robustness.run_probes()}
    assert by_name["broken-policy"]["decision"] == "ask"
    assert by_name["unparseable-input"]["decision"] == "ask"
    assert by_name["unconfigured-invisible"]["decision"] == "silent"


def test_proof_attests_robustness():
    key = Ed25519PrivateKey.generate()
    proof = adversary.build_proof(load_policy("examples/safe.yaml"), key)
    assert proof["robustness_total"] >= 3
    assert proof["robustness_failed_open"] == 0
    # a fail-open record in the chain would flip the signed proof to red
    assert any("probe" in r for r in proof["chain"])
