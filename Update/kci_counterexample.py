"""Check the manuscript's responder logic using ideal KEM and AEAD interfaces.

This is a functional counterexample, not a cryptographic implementation,
benchmark, field attack, or machine-checked proof. No manuscript inputs change.
"""

import hashlib
import hmac
import json
import secrets
from pathlib import Path


def encode(*fields):
    return b"".join(len(field).to_bytes(2, "big") + field for field in fields)


def digest(message):
    return hashlib.sha3_256(message).digest()


def derive(message):
    extracted = hmac.digest(bytes(32), message, "sha256")
    return hmac.digest(extracted, b"\x01", "sha256")


def mac(key, *fields):
    return hmac.digest(key, encode(*fields), "sha256")


class IdealKEM:
    def __init__(self):
        self.private_to_public = {}
        self.encapsulations = {}
        self.decapsulation_log = []

    def keygen(self):
        public_key, private_key = secrets.token_bytes(32), secrets.token_bytes(32)
        self.private_to_public[private_key] = public_key
        return public_key, private_key

    def encapsulate(self, public_key):
        shared_secret, ciphertext = secrets.token_bytes(32), secrets.token_bytes(32)
        self.encapsulations[ciphertext] = (public_key, shared_secret)
        return shared_secret, ciphertext

    def decapsulate(self, ciphertext, private_key, caller):
        public_key, shared_secret = self.encapsulations[ciphertext]
        if self.private_to_public[private_key] != public_key:
            raise ValueError("Wrong recipient key")
        self.decapsulation_log.append((caller, private_key))
        return shared_secret


class IdealAEAD:
    def __init__(self):
        self.sealed = {}
        self.open_log = []

    def seal(self, key, plaintext, associated_data):
        ciphertext = secrets.token_bytes(32)
        self.sealed[ciphertext] = (key, plaintext, associated_data)
        return ciphertext

    def open(self, key, ciphertext, associated_data, caller):
        expected_key, plaintext, expected_data = self.sealed[ciphertext]
        if key != expected_key or associated_data != expected_data:
            raise ValueError("Authentication failed")
        self.open_log.append((caller, ciphertext))
        return plaintext


def attacker_finish(kem, known_static, owned_ephemeral_private, token_raw, hash1,
                    ephemeral_ciphertext, rsa_ciphertext, responder_nonce):
    ephemeral_secret = kem.decapsulate(
        ephemeral_ciphertext, owned_ephemeral_private, "attacker"
    )
    hash2 = digest(encode(hash1, ephemeral_ciphertext, rsa_ciphertext, responder_nonce))
    master = derive(encode(known_static, ephemeral_secret, hash2))
    challenge = mac(master, b'"challenge"', hash2, token_raw)
    response = mac(master, b'"response"', hash2, challenge)
    session = derive(encode(b"SESSION", master, hash2))
    return response, session


def check_trial():
    kem, aead = IdealKEM(), IdealAEAD()
    initiator_rsa_public, initiator_rsa_private = kem.keygen()
    responder_rsa_public, responder_rsa_private = kem.keygen()
    responder_static_public, responder_static_private = kem.keygen()
    attacker_ephemeral_public, attacker_ephemeral_private = kem.keygen()
    claimed_identity = b"honest-registered-initiator-A"
    initiator_nonce, token_raw = secrets.token_bytes(32), secrets.token_bytes(32)
    fingerprint = digest(attacker_ephemeral_public)
    attacker_static, static_ciphertext = kem.encapsulate(responder_static_public)
    verify_key = derive(encode(b"DOS_SHIELD", attacker_static,
                               initiator_nonce, claimed_identity))
    mac1 = mac(verify_key, claimed_identity, attacker_ephemeral_public,
               initiator_nonce, static_ciphertext)
    sender_rsa_secret, sender_rsa_ciphertext = kem.encapsulate(responder_rsa_public)
    token = (claimed_identity, fingerprint, initiator_nonce, token_raw)
    token_ad = encode(claimed_identity, initiator_nonce, mac1)
    token_ciphertext = aead.seal(sender_rsa_secret, token, token_ad)
    message1 = encode(claimed_identity, attacker_ephemeral_public, static_ciphertext,
                      sender_rsa_ciphertext, token_ciphertext, initiator_nonce, mac1)
    hash1 = digest(message1)

    responder_static = kem.decapsulate(static_ciphertext, responder_static_private,
                                       "honest-responder")
    responder_verify_key = derive(encode(b"DOS_SHIELD", responder_static,
                                         initiator_nonce, claimed_identity))
    expected_mac1 = mac(responder_verify_key, claimed_identity,
                        attacker_ephemeral_public, initiator_nonce, static_ciphertext)
    assert hmac.compare_digest(mac1, expected_mac1)
    responder_token_key = kem.decapsulate(sender_rsa_ciphertext, responder_rsa_private,
                                          "honest-responder")
    identity_in_token, fingerprint_in_token, nonce_in_token, received_token = aead.open(
        responder_token_key, token_ciphertext, token_ad, "honest-responder"
    )
    assert identity_in_token == claimed_identity
    assert fingerprint_in_token == digest(attacker_ephemeral_public)
    assert nonce_in_token == initiator_nonce

    responder_nonce = secrets.token_bytes(32)
    responder_ephemeral, ephemeral_ciphertext = kem.encapsulate(attacker_ephemeral_public)
    challenge_key, challenge_rsa_ciphertext = kem.encapsulate(initiator_rsa_public)
    hash2 = digest(encode(hash1, ephemeral_ciphertext, challenge_rsa_ciphertext,
                          responder_nonce))
    responder_master = derive(encode(responder_static, responder_ephemeral, hash2))
    responder_challenge = mac(responder_master, b'"challenge"', hash2, received_token)
    challenge_ciphertext = aead.seal(challenge_key, responder_challenge, hash2)

    forged_response, attacker_session = attacker_finish(
        kem, attacker_static, attacker_ephemeral_private, token_raw, hash1,
        ephemeral_ciphertext, challenge_rsa_ciphertext, responder_nonce
    )
    expected_response = mac(responder_master, b'"response"', hash2, responder_challenge)
    responder_session = derive(encode(b"SESSION", responder_master, hash2))
    assert hmac.compare_digest(forged_response, expected_response)
    assert attacker_session == responder_session
    assert kem.decapsulation_log == [
        ("honest-responder", responder_static_private),
        ("honest-responder", responder_rsa_private),
        ("attacker", attacker_ephemeral_private),
    ]
    assert all(private_key != initiator_rsa_private
               for _, private_key in kem.decapsulation_log)
    assert all(ciphertext != challenge_ciphertext for _, ciphertext in aead.open_log)
    wrong_response = bytes([forged_response[0] ^ 1]) + forged_response[1:]
    assert not hmac.compare_digest(wrong_response, expected_response)
    return True


def main():
    trials = 1000
    successes = sum(check_trial() for _ in range(trials))
    result = {
        "scope": "Functional counterexample to Algorithm 2 as written in main.tex",
        "primitives": "Ideal KEM and AEAD; SHA3-256, HMAC-SHA256, one-block HKDF",
        "encoding": "Length-prefixed fields; two-byte unsigned lengths",
        "trials": trials,
        "responder_accepts_claimed_honest_identity": successes,
        "attacker_computes_responder_session_key": successes,
        "honest_initiator_sessions_started": 0,
        "long_term_secret_keys_disclosed_to_attacker": 0,
        "attacker_decapsulates_with_honest_initiator_rsa_key": False,
        "encrypted_challenge_ever_opened": False,
        "altered_response_rejected_in_every_trial": True,
        "randomness": "Fresh secrets.token_bytes values; conclusion does not depend on seed",
        "is_original_experiment_or_crypto_benchmark": False,
        "is_machine_checked_security_proof": False,
        "reason": "Response depends only on master, transcript, and a recomputable challenge; master omits RSA authentication secrets",
    }
    output = Path("analysis/kci_counterexample.json")
    output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()