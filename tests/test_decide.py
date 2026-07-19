import pytest

from railward import decide, load_policy

SAFE = load_policy("examples/safe.yaml")


def v(request):
    return decide(request, SAFE).verdict


def test_default_deny_on_empty_policy():
    p = load_policy("default: deny\nrules: []", text=True)
    assert decide({"action": "bash", "command": "ls"}, p).verdict == "deny"


def test_malformed_requests_denied():
    assert decide("not-a-dict", SAFE).verdict == "deny"
    assert decide({}, SAFE).verdict == "deny"
    assert decide({"action": ""}, SAFE).verdict == "deny"
    assert decide({"action": "write", "path": 123}, SAFE).verdict == "deny"


def test_allow_workspace_write():
    assert v({"action": "write", "path": "work/out.txt"}) == "allow"


def test_ask_for_write_outside_workspace():
    assert v({"action": "write", "path": "docs/readme.md"}) == "ask"


def test_deny_secrets_for_any_action():
    assert v({"action": "read", "path": "secrets/prod.env"}) == "deny"
    assert v({"action": "write", "path": "app/secrets/key.pem"}) == "deny"


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "RM -RF /",                       # case evasion
        "/bin/rm -rf /",                  # absolute-path evasion
        "rm    -rf     /",                # whitespace evasion
        "rm -fr /",                       # flag reorder
        "rm --recursive --force /",       # long flags
        "echo ok; rm -rf /",              # ; injection
        "true && rm -rf /",               # && injection
        "cat x | rm -rf /",               # pipe injection
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        ":(){ :|:& };:",                  # fork bomb
        "git push origin main --force",
    ],
)
def test_deny_destructive_and_evasions(command):
    assert v({"action": "bash", "command": command}) == "deny"


def test_deny_path_escape():
    assert v({"action": "write", "path": "work/../../etc/passwd"}) == "deny"


def test_deny_absolute_write():
    assert v({"action": "write", "path": "/etc/passwd"}) == "deny"


def test_allow_safe_reads_and_bash():
    assert v({"action": "bash", "command": "ls -la"}) == "allow"
    assert v({"action": "read", "path": "README.md"}) == "allow"


def test_unparseable_command_denied():
    assert v({"action": "bash", "command": "echo 'unbalanced"}) == "deny"


def test_oversized_command_denied():
    assert v({"action": "bash", "command": "a " * 60000}) == "deny"
