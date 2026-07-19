import pytest

from railward import load_policy


def test_default_allow_is_rejected():
    with pytest.raises(ValueError):
        load_policy("default: allow\nrules: []", text=True)


def test_rule_without_effect_is_rejected():
    with pytest.raises(ValueError):
        load_policy("rules:\n  - action: bash\n", text=True)


def test_bad_effect_is_rejected():
    with pytest.raises(ValueError):
        load_policy("rules:\n  - effect: maybe\n", text=True)


def test_loads_example_policy():
    p = load_policy("examples/safe.yaml")
    assert p.default == "deny"
    assert len(p.rules) >= 5
