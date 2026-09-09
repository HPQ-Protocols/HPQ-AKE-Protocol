"""Functional checks of the authorized KDF correction, not a security proof.

The frozen old counterexample is retained. Its complete M1/M2 construction
is reused with exact, asserted substitutions for a differential regression.
The other checks exercise the missing-secret boundary with ideal KEM/AEAD.
No historical benchmark or simulation input is changed.
"""

import hashlib
import hmac
import inspect
import json
import secrets
from pathlib import Path

import kci_counterexample as original
from kci_counterexample import IdealAEAD, IdealKEM, derive, digest, encode, mac


def master_key(static_secret, ephemeral_secret, rsa_secret, transcript):
    material = encode(static_secret, ephemeral_secret, rsa_secret, transcript)
    extracted = hmac.digest(bytes(32), material, "sha256")
    return hmac.digest(extracted, b"HPQ-AKE/master\x01", "sha256")


def response(master, transcript, token):
    challenge = mac(master, b'"challenge"', transcript, token)
    return mac(master, b'"response"', transcript, challenge)


def revised_original_attack():
    source = inspect.getsource(original.check_trial)
    changes = {
        "def check_trial():": "def revised_trial():",
        "responder_master = derive(encode(responder_static, responder_ephemeral, hash2))":
            "responder_master = master_key(responder_static, responder_ephemeral, challenge_key, hash2)",
        "assert hmac.compare_digest(forged_response, expected_response)":
            "assert not hmac.compare_digest(forged_response, expected_response)",
        "assert attacker_session == responder_session":
            "assert attacker_session != responder_session",
    }
    for before, after in changes.items():
        assert source.count(before) == 1
        source = source.replace(before, after)
    namespace = dict(vars(original), master_key=master_key)
    exec(compile(source, "<asserted-revised-counterexample>", "exec"), namespace)
    return namespace["revised_trial"]


def check_honest_confirmation():
    kem, aead = IdealKEM(), IdealAEAD()
    responder_public, responder_private = kem.keygen()
    initiator_public, initiator_private = kem.keygen()
    ephemeral_public, ephemeral_private = kem.keygen()
    static_a, static_ciphertext = kem.encapsulate(responder_public)
    static_b = kem.decapsulate(static_ciphertext, responder_private, "B")
    ephemeral_b, ephemeral_ciphertext = kem.encapsulate(ephemeral_public)
    rsa_b, rsa_ciphertext = kem.encapsulate(initiator_public)
    transcript = digest(encode(static_ciphertext, ephemeral_ciphertext,
                               rsa_ciphertext, secrets.token_bytes(32)))
    token = secrets.token_bytes(32)
    master_b = master_key(static_b, ephemeral_b, rsa_b, transcript)
    challenge_b = mac(master_b, b'"challenge"', transcript, token)
    encrypted_challenge = aead.seal(rsa_b, challenge_b, transcript)
    ephemeral_a = kem.decapsulate(ephemeral_ciphertext, ephemeral_private, "A")
    rsa_a = kem.decapsulate(rsa_ciphertext, initiator_private, "A")
    master_a = master_key(static_a, ephemeral_a, rsa_a, transcript)
    opened = aead.open(rsa_a, encrypted_challenge, transcript, "A")
    assert opened == mac(master_a, b'"challenge"', transcript, token)
    assert response(master_a, transcript, token) == response(master_b, transcript, token)
    assert derive(encode(b"SESSION", master_a, transcript)) == derive(
        encode(b"SESSION", master_b, transcript))
    other_transcript = digest(transcript)
    assert response(master_a, other_transcript, token) != response(master_b, transcript, token)
    try:
        aead.open(rsa_a, encrypted_challenge, other_transcript, "A")
    except ValueError:
        pass
    else:
        raise AssertionError("Altered associated data accepted")
    return True


def check_missing_secret(victim):
    kem = IdealKEM()
    peer_public, peer_private = kem.keygen()
    protected, ciphertext = kem.encapsulate(peer_public)
    known_static, known_ephemeral, known_rsa = [secrets.token_bytes(32) for _ in range(3)]
    transcript, token = secrets.token_bytes(32), secrets.token_bytes(32)
    guessed = secrets.token_bytes(32)
    if victim == "A":
        honest = master_key(protected, known_ephemeral, known_rsa, transcript)
        attempted = master_key(guessed, known_ephemeral, known_rsa, transcript)
        recovered = kem.decapsulate(ciphertext, peer_private, "negative-control-peer-compromise")
        compromised_peer = master_key(recovered, known_ephemeral, known_rsa, transcript)
        expected = mac(honest, b'"challenge"', transcript, token)
        assert mac(attempted, b'"challenge"', transcript, token) != expected
        assert mac(compromised_peer, b'"challenge"', transcript, token) == expected
    else:
        honest = master_key(known_static, known_ephemeral, protected, transcript)
        attempted = master_key(known_static, known_ephemeral, guessed, transcript)
        recovered = kem.decapsulate(ciphertext, peer_private, "negative-control-peer-compromise")
        compromised_peer = master_key(known_static, known_ephemeral, recovered, transcript)
        assert response(attempted, transcript, token) != response(honest, transcript, token)
        assert response(compromised_peer, transcript, token) == response(honest, transcript, token)
    return True


def main():
    trials = 1000
    revised_trial = revised_original_attack()
    checks = {
        "original_counterexample_still_accepts": original.check_trial,
        "same_attack_rejected_after_correction": revised_trial,
        "honest_confirmation_and_session_agreement": check_honest_confirmation,
        "A_victim_missing_static_MLKEM_input": lambda: check_missing_secret("A"),
        "B_victim_missing_peer_RSA_input": lambda: check_missing_secret("B"),
    }
    result = {
        "scope": "Functional ideal-primitive regression and missing-input boundary checks",
        "trials_per_check": trials,
        "passed": {name: sum(check() for _ in range(trials)) for name, check in checks.items()},
        "master_kdf": "HKDF-SHA256, zero salt, info=HPQ-AKE/master, output=32 bytes",
        "encoding": "Same two-byte length-prefix helper as the frozen counterexample",
        "randomness": "secrets.token_bytes; not the seed of any historical simulation",
        "negative_controls": "Peer-key disclosure restores tag computation in both missing-input checks",
        "limits": "Not exhaustive adversary exploration, real KEM implementation, timing benchmark, or reduction proof",
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    Path("analysis/kci_revision_checks.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()