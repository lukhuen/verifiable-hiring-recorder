"""Unit tests for Verifiable Hiring Recorder."""

from verifiable_hiring import (
    HiringDecisionNode,
    KeyPair,
    MerkleTree,
    VerifiableHiringRecorder,
    sha256_hex,
)


def test_ed25519_roundtrip():
    kp = KeyPair.generate("vendor")
    msg = b"hello"
    sig = kp.sign(msg)
    assert kp.verify(sig, msg)
    assert not kp.verify(sig, b"other")


def test_chain_integrity_and_signatures():
    r = VerifiableHiringRecorder()
    r.log_decision("a", 90.0, 80.0, "INTERVIEW")
    r.log_decision("b", 50.0, 80.0, "AUTO_REJECT")
    assert r.verify_chain_integrity()
    assert r.chain[0].verify_signatures(r.vendor.public, r.employer.public)


def test_merkle_proof_in_candidate_disclosure():
    r = VerifiableHiringRecorder()
    for i in range(8):
        r.log_decision(f"c{i}", 70.0 + i, 80.0, "AUTO_REJECT")
    r.publish_epoch_root()
    proof = r.get_candidate_proof("c3")
    assert proof is not None
    assert proof["proof_valid"] is True
    assert MerkleTree.verify(proof["leaf_hash"], proof["merkle_proof"], proof["merkle_root"])


def test_naive_tamper_detected():
    r = VerifiableHiringRecorder()
    for i in range(5):
        r.log_decision(f"c{i}", 70.0, 80.0, "AUTO_REJECT")
    r.naive_tamper_threshold(2, 99.0)
    assert not r.verify_chain_integrity()


def test_suffix_rewrite_defeats_local_but_not_anchor():
    r = VerifiableHiringRecorder()
    for i in range(5):
        r.log_decision(f"c{i}", 70.0, 80.0, "AUTO_REJECT")
    r.publish_epoch_root()
    r.rewrite_suffix_from(2, 99.0)
    assert r.verify_chain_integrity()
    assert not r.verify_against_anchor()


def test_deletion_defeats_local_but_not_anchor():
    r = VerifiableHiringRecorder()
    for i in range(6):
        r.log_decision(f"c{i}", 70.0, 80.0, "AUTO_REJECT")
    r.publish_epoch_root()
    r.delete_record(2)
    assert r.verify_chain_integrity()
    assert not r.verify_against_anchor()


def test_genesis_hash_stable():
    assert sha256_hex("GENESIS_NODE") == sha256_hex("GENESIS_NODE")
