from cpm_server.security.tokens import generate_token, hash_token, parse_prefix, verify_token


def test_generated_token_roundtrip():
    t = generate_token()
    assert t.plaintext.startswith("cpm_")
    assert parse_prefix(t.plaintext) == t.prefix
    assert verify_token(t.plaintext, t.token_hash)
    assert t.plaintext not in t.token_hash  # only the hash is stored


def test_tokens_are_unique():
    assert generate_token().plaintext != generate_token().plaintext


def test_wrong_secret_is_rejected():
    t = generate_token()
    assert not verify_token(t.plaintext + "x", t.token_hash)
    assert not verify_token("cpm_" + t.prefix + "_other", t.token_hash)


def test_secret_may_contain_underscores():
    assert parse_prefix("cpm_abcd1234_se_cr_et") == "abcd1234"


def test_malformed_tokens():
    for bad in ["", "cpm", "cpm_", "cpm__x", "cpm_abc", "xyz_abc_def", "Bearer cpm_a_b"]:
        assert parse_prefix(bad) is None, bad


def test_hash_is_deterministic_hex():
    assert hash_token("a") == hash_token("a")
    assert len(hash_token("a")) == 64
