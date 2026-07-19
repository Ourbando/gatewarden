from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from railward import log as plog


def test_chain_is_deterministic_and_linked():
    entries = [{"a": 1}, {"a": 2}]
    c1 = plog.build_chain(entries)
    c2 = plog.build_chain(entries)
    assert plog.head_hash(c1) == plog.head_hash(c2)
    assert c1[1]["prev"] == c1[0]["hash"]


def test_tamper_breaks_verification():
    key = Ed25519PrivateKey.generate()
    chain = plog.build_chain([{"x": 1}, {"x": 2}, {"x": 3}])
    sig = plog.sign_head(chain, key)
    ok, _ = plog.verify_chain(chain, sig, key.public_key())
    assert ok
    chain[1]["x"] = 99  # alter an earlier record
    ok, msg = plog.verify_chain(chain, sig, key.public_key())
    assert not ok
    assert "seq 1" in msg


def test_wrong_key_fails():
    k1, k2 = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    chain = plog.build_chain([{"x": 1}])
    sig = plog.sign_head(chain, k1)
    ok, _ = plog.verify_chain(chain, sig, k2.public_key())
    assert not ok


def test_key_roundtrip(tmp_path):
    priv = str(tmp_path / "k.pem")
    key = plog.new_key(priv)
    reloaded = plog.load_private(priv)
    assert reloaded.public_key().public_bytes_raw() == key.public_key().public_bytes_raw()
    pub = plog.load_public(str(tmp_path / "k.pub"))
    chain = plog.build_chain([{"x": 1}])
    sig = plog.sign_head(chain, key)
    ok, _ = plog.verify_chain(chain, sig, pub)
    assert ok
