"""
Verifiable Hiring Recorder — research prototype for FAccT submission.

Integrity properties under an explicit threat model. Does NOT prove fairness.

Cryptography:
  - Ed25519 dual signatures (vendor + employer) via the cryptography library
  - SHA-256 hash chaining
  - Merkle selective disclosure with inclusion proofs
  - External epoch-root anchoring (simulated independent custody)

Run:
  python verifiable_hiring.py
  python verifiable_hiring.py --bench
  pytest tests/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError:  # pragma: no cover
    plt = None
    np = None


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes | str) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


@dataclass
class KeyPair:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey
    role: str

    @classmethod
    def generate(cls, role: str) -> "KeyPair":
        priv = Ed25519PrivateKey.generate()
        return cls(private=priv, public=priv.public_key(), role=role)

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            self.public.verify(signature, message)
            return True
        except Exception:
            return False

    def public_hex(self) -> str:
        return self.public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


@dataclass
class HiringDecisionNode:
    timestamp: str
    candidate_id: str
    ai_score: float
    threshold: float
    outcome: str
    model_version: str
    prev_hash: str
    payload: str
    node_hash: str
    vendor_signature: Optional[bytes] = None
    employer_signature: Optional[bytes] = None

    @classmethod
    def create(
        cls,
        candidate_id: str,
        ai_score: float,
        threshold: float,
        outcome: str,
        prev_hash: str,
        model_version: str = "v1.0",
        timestamp: Optional[str] = None,
    ) -> "HiringDecisionNode":
        import datetime

        ts = timestamp or datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = json.dumps(
            {
                "ts": ts,
                "cid": candidate_id,
                "score": ai_score,
                "threshold": threshold,
                "outcome": outcome,
                "model": model_version,
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return cls(
            timestamp=ts,
            candidate_id=candidate_id,
            ai_score=ai_score,
            threshold=threshold,
            outcome=outcome,
            model_version=model_version,
            prev_hash=prev_hash,
            payload=payload,
            node_hash=sha256_hex(payload),
        )

    def dual_sign(self, vendor: KeyPair, employer: KeyPair) -> None:
        msg = bytes.fromhex(self.node_hash)
        self.vendor_signature = vendor.sign(msg)
        self.employer_signature = employer.sign(msg)

    def verify_signatures(self, vendor_pub: Ed25519PublicKey, employer_pub: Ed25519PublicKey) -> bool:
        if not self.vendor_signature or not self.employer_signature:
            return False
        msg = bytes.fromhex(self.node_hash)
        try:
            vendor_pub.verify(self.vendor_signature, msg)
            employer_pub.verify(self.employer_signature, msg)
            return True
        except Exception:
            return False


class MerkleTree:
    def __init__(self, leaves: List[str]):
        if not leaves:
            raise ValueError("Merkle tree requires at least one leaf")
        self.leaves = leaves[:]
        self.levels: List[List[str]] = [leaves[:]]
        level = leaves[:]
        while len(level) > 1:
            nxt: List[str] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                nxt.append(sha256_hex(left + right))
            self.levels.append(nxt)
            level = nxt

    @property
    def root(self) -> str:
        return self.levels[-1][0]

    def proof(self, index: int) -> List[Tuple[str, str]]:
        path: List[Tuple[str, str]] = []
        idx = index
        for level in self.levels[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1 if idx + 1 < len(level) else idx
                side = "R"
            else:
                sibling_idx = idx - 1
                side = "L"
            path.append((level[sibling_idx], side))
            idx //= 2
        return path

    @staticmethod
    def verify(leaf: str, proof: List[Tuple[str, str]], root: str) -> bool:
        h = leaf
        for sibling, side in proof:
            h = sha256_hex(sibling + h) if side == "L" else sha256_hex(h + sibling)
        return h == root


@dataclass
class ExternalAnchor:
    """Simulates an independently custodied epoch-root publication channel."""

    published_roots: List[Dict[str, str]] = field(default_factory=list)

    def publish(self, root: str, epoch_id: str) -> None:
        self.published_roots.append({"epoch_id": epoch_id, "root": root})

    def latest(self) -> Optional[Dict[str, str]]:
        return self.published_roots[-1] if self.published_roots else None

    def matches(self, root: str) -> bool:
        latest = self.latest()
        return bool(latest) and latest["root"] == root


class VerifiableHiringRecorder:
    def __init__(self, vendor: Optional[KeyPair] = None, employer: Optional[KeyPair] = None):
        self.vendor = vendor or KeyPair.generate("vendor")
        self.employer = employer or KeyPair.generate("employer")
        self.chain: List[HiringDecisionNode] = []
        self.current_hash = sha256_hex("GENESIS_NODE")
        self.anchor = ExternalAnchor()
        self.epoch_counter = 0

    def log_decision(
        self,
        candidate_id: str,
        ai_score: float,
        threshold: float,
        outcome: str,
        model_version: str = "v1.0",
    ) -> str:
        node = HiringDecisionNode.create(
            candidate_id, ai_score, threshold, outcome, self.current_hash, model_version
        )
        node.dual_sign(self.vendor, self.employer)
        self.chain.append(node)
        self.current_hash = node.node_hash
        return node.node_hash

    def publish_epoch_root(self) -> str:
        self.epoch_counter += 1
        root = self.merkle_for_chain().root
        self.anchor.publish(root, f"epoch-{self.epoch_counter}")
        return root

    def verify_chain_integrity(self, check_signatures: bool = True) -> bool:
        expected_prev = sha256_hex("GENESIS_NODE")
        for node in self.chain:
            if sha256_hex(node.payload) != node.node_hash:
                return False
            if node.prev_hash != expected_prev:
                return False
            if check_signatures and not node.verify_signatures(
                self.vendor.public, self.employer.public
            ):
                return False
            expected_prev = node.node_hash
        return True

    def verify_against_anchor(self) -> bool:
        if not self.verify_chain_integrity():
            return False
        if self.anchor.latest() is None:
            return True
        return self.anchor.matches(self.merkle_for_chain().root)

    def get_candidate_proof(self, candidate_id: str) -> Optional[Dict[str, Any]]:
        """Return selective disclosure package: fields + Merkle inclusion + sig flags."""
        for idx, node in enumerate(self.chain):
            if node.candidate_id == candidate_id:
                tree = self.merkle_for_chain()
                proof = tree.proof(idx)
                return {
                    "candidate_id": node.candidate_id,
                    "ai_score": node.ai_score,
                    "threshold": node.threshold,
                    "outcome": node.outcome,
                    "model_version": node.model_version,
                    "leaf_hash": node.node_hash,
                    "merkle_root": tree.root,
                    "merkle_proof": proof,
                    "proof_valid": MerkleTree.verify(node.node_hash, proof, tree.root),
                    "vendor_sig_valid": node.verify_signatures(
                        self.vendor.public, self.employer.public
                    ),
                    "vendor_pubkey": self.vendor.public_hex(),
                    "employer_pubkey": self.employer.public_hex(),
                    "anchored": self.anchor.matches(tree.root)
                    if self.anchor.latest()
                    else False,
                }
        return None

    def merkle_for_chain(self) -> MerkleTree:
        return MerkleTree([n.node_hash for n in self.chain])

    def naive_tamper_threshold(self, index: int, new_threshold: float) -> None:
        node = self.chain[index]
        node.threshold = new_threshold
        node.payload = json.dumps(
            {
                "ts": node.timestamp,
                "cid": node.candidate_id,
                "score": node.ai_score,
                "threshold": new_threshold,
                "outcome": node.outcome,
                "model": node.model_version,
                "prev_hash": node.prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    def rewrite_suffix_from(self, index: int, new_threshold: float) -> None:
        """Privileged rewrite: edit and recompute hashes + re-sign with stolen keys."""
        node = self.chain[index]
        prev = node.prev_hash
        rebuilt: List[HiringDecisionNode] = self.chain[:index]
        first = HiringDecisionNode.create(
            node.candidate_id,
            node.ai_score,
            new_threshold,
            node.outcome,
            prev,
            node.model_version,
            timestamp=node.timestamp,
        )
        first.dual_sign(self.vendor, self.employer)
        rebuilt.append(first)
        cur = first.node_hash
        for later in self.chain[index + 1 :]:
            nxt = HiringDecisionNode.create(
                later.candidate_id,
                later.ai_score,
                later.threshold,
                later.outcome,
                cur,
                later.model_version,
                timestamp=later.timestamp,
            )
            nxt.dual_sign(self.vendor, self.employer)
            rebuilt.append(nxt)
            cur = nxt.node_hash
        self.chain = rebuilt
        self.current_hash = cur

    def delete_record(self, index: int) -> None:
        """Deletion attack: remove a node and rebuild suffix (privileged)."""
        if index >= len(self.chain):
            return
        if index == 0:
            prev = sha256_hex("GENESIS_NODE")
            rebuilt = []
        else:
            prev = self.chain[index - 1].node_hash
            rebuilt = self.chain[:index]
        for later in self.chain[index + 1 :]:
            nxt = HiringDecisionNode.create(
                later.candidate_id,
                later.ai_score,
                later.threshold,
                later.outcome,
                prev,
                later.model_version,
                timestamp=later.timestamp,
            )
            nxt.dual_sign(self.vendor, self.employer)
            rebuilt.append(nxt)
            prev = nxt.node_hash
        self.chain = rebuilt
        self.current_hash = prev if rebuilt else sha256_hex("GENESIS_NODE")


def demo() -> None:
    print("--- Verifiable Hiring Prototype (Ed25519 + Merkle + Anchor) ---")
    recorder = VerifiableHiringRecorder()
    for cid, score, outcome in [
        ("candidate_001_alice", 85.5, "INTERVIEW"),
        ("candidate_002_bob", 45.0, "AUTO_REJECT"),
        ("candidate_003_mobley", 79.9, "AUTO_REJECT"),
        ("candidate_004_charlie", 92.0, "INTERVIEW"),
    ]:
        recorder.log_decision(cid, score, 80.0, outcome)

    root = recorder.publish_epoch_root()
    print(f"[ANCHOR] Published epoch root: {root[:24]}...")
    print(f"[AUDIT] Chain+sigs intact? {recorder.verify_chain_integrity()}")
    print(f"[AUDIT] Matches external anchor? {recorder.verify_against_anchor()}")

    proof = recorder.get_candidate_proof("candidate_003_mobley")
    assert proof is not None
    print("\n[DISCOVERY] Selective Merkle disclosure:")
    print(
        json.dumps(
            {k: v for k, v in proof.items() if k not in ("merkle_proof",)},
            indent=2,
        )
    )
    print(f"  merkle_proof_len={len(proof['merkle_proof'])} proof_valid={proof['proof_valid']}")

    print("\n--- Attack A: naïve in-place edit ---")
    a = VerifiableHiringRecorder()
    for i in range(4):
        a.log_decision(f"c{i}", 70 + i, 80.0, "AUTO_REJECT")
    a.naive_tamper_threshold(2, 99.0)
    print(f"Local verify after naïve edit: {a.verify_chain_integrity()} (expect False)")

    print("\n--- Attack B: privileged suffix rewrite ---")
    b = VerifiableHiringRecorder()
    for i in range(4):
        b.log_decision(f"c{i}", 70 + i, 80.0, "AUTO_REJECT")
    b.publish_epoch_root()
    b.rewrite_suffix_from(2, 99.0)
    print(f"Local verify after rewrite: {b.verify_chain_integrity()} (expect True)")
    print(f"Anchor check after rewrite: {b.verify_against_anchor()} (expect False)")


def _time_stats(fn, repeats: int = 7, warmup: int = 2) -> Dict[str, float]:
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)
    return {
        "mean_ms": statistics.mean(samples),
        "stdev_ms": statistics.stdev(samples) if len(samples) > 1 else 0.0,
        "min_ms": min(samples),
        "max_ms": max(samples),
        "n": repeats,
    }


def run_benchmarks(out_dir: Path) -> Dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    sizes = [100, 500, 1000, 5000, 10000]
    local_us = []
    local_us_stdev = []
    ed25519_ms = []
    ed25519_stdev = []
    verify_ms = []
    merkle_ms = []
    flat_bytes = []
    selective_bytes = []

    # Modeled remote KMS RTT (NOT measured against cloud KMS)
    MODELED_KMS_RTT_MS = 12.0
    MODELED_DUAL_KMS_MS = 2 * MODELED_KMS_RTT_MS

    for n in sizes:
        def log_hash_only():
            # Measure payload+hash only by creating nodes without signing
            prev = sha256_hex("GENESIS_NODE")
            for i in range(n):
                node = HiringDecisionNode.create(f"c_{i:05d}", 75.0, 80.0, "AUTO_REJECT", prev)
                prev = node.node_hash

        stats_h = _time_stats(log_hash_only, repeats=5)
        local_us.append((stats_h["mean_ms"] / n) * 1000.0)
        local_us_stdev.append((stats_h["stdev_ms"] / n) * 1000.0)

        def log_ed25519():
            r = VerifiableHiringRecorder()
            for i in range(n):
                r.log_decision(f"c_{i:05d}", 75.0, 80.0, "AUTO_REJECT")

        stats_e = _time_stats(log_ed25519, repeats=3)
        ed25519_ms.append(stats_e["mean_ms"] / n)
        ed25519_stdev.append(stats_e["stdev_ms"] / n)

        r = VerifiableHiringRecorder()
        for i in range(n):
            score = 50 + (i % 50)
            r.log_decision(
                f"c_{i:05d}",
                float(score),
                80.0,
                "INTERVIEW" if score >= 80 else "AUTO_REJECT",
            )
        verify_ms.append(_time_stats(r.verify_chain_integrity, repeats=5)["mean_ms"])
        merkle_ms.append(_time_stats(r.merkle_for_chain, repeats=5)["mean_ms"])
        tree = r.merkle_for_chain()
        target = n // 2
        proof = tree.proof(target)
        flat = [
            {
                "cid": nd.candidate_id,
                "score": nd.ai_score,
                "threshold": nd.threshold,
                "outcome": nd.outcome,
                "hash": nd.node_hash,
            }
            for nd in r.chain
        ]
        selective = {
            "cid": r.chain[target].candidate_id,
            "score": r.chain[target].ai_score,
            "threshold": r.chain[target].threshold,
            "outcome": r.chain[target].outcome,
            "leaf": r.chain[target].node_hash,
            "root": tree.root,
            "proof": proof,
        }
        flat_bytes.append(len(json.dumps(flat).encode()))
        selective_bytes.append(len(json.dumps(selective).encode()))

    trials = 100
    naive_local = 0
    rewrite_local = 0
    rewrite_anchor = 0
    delete_local = 0
    delete_anchor = 0

    for i in range(trials):
        a = VerifiableHiringRecorder()
        for j in range(40):
            a.log_decision(f"c{j}", 70.0, 80.0, "AUTO_REJECT")
        a.naive_tamper_threshold(i % 40, 99.0)
        if not a.verify_chain_integrity():
            naive_local += 1

        b = VerifiableHiringRecorder()
        for j in range(40):
            b.log_decision(f"c{j}", 70.0, 80.0, "AUTO_REJECT")
        b.publish_epoch_root()
        b.rewrite_suffix_from(i % 40, 99.0)
        if not b.verify_chain_integrity():
            rewrite_local += 1
        if not b.verify_against_anchor():
            rewrite_anchor += 1

        c = VerifiableHiringRecorder()
        for j in range(40):
            c.log_decision(f"c{j}", 70.0, 80.0, "AUTO_REJECT")
        c.publish_epoch_root()
        c.delete_record(i % 40)
        if not c.verify_chain_integrity():
            delete_local += 1
        if not c.verify_against_anchor():
            delete_anchor += 1

    # --- Epoch cadence trade-off ---
    # Between publishes, a privileged rewriter can alter unpublished decisions
    # without failing the *last* published root until the next audit against that root
    # after the rewrite of already-published leaves.
    epoch_sizes = [1, 10, 50, 100, 500, 1000]
    undetectable_windows = list(epoch_sizes)  # max decisions alterable before next anchor

    batch_ks = [1, 10, 50, 100]
    batch_ms_per_decision = []
    for k in batch_ks:
        def batched(k=k):
            vendor = KeyPair.generate("v")
            employer = KeyPair.generate("e")
            prev = sha256_hex("GENESIS_NODE")
            batch_hashes = []
            for i in range(1000):
                node = HiringDecisionNode.create(f"c{i}", 70.0, 80.0, "AUTO_REJECT", prev)
                prev = node.node_hash
                batch_hashes.append(node.node_hash)
                if len(batch_hashes) == k or i == 999:
                    root = MerkleTree(batch_hashes).root
                    msg = bytes.fromhex(root)
                    vendor.sign(msg)
                    employer.sign(msg)
                    batch_hashes = []

        stats_b = _time_stats(batched, repeats=3, warmup=1)
        batch_ms_per_decision.append(stats_b["mean_ms"] / 1000.0)

    # Detection of rewrite of an already-anchored leaf, by epoch size (stability check)
    cadence_detect_anchor = []
    cadence_detect_local = []
    trials_c = 30
    for epoch in epoch_sizes:
        d_local = 0
        d_anchor = 0
        for _ in range(trials_c):
            r2 = VerifiableHiringRecorder()
            for j in range(max(epoch, 2)):
                r2.log_decision(f"a{j}", 70.0, 80.0, "AUTO_REJECT")
            r2.publish_epoch_root()
            r2.rewrite_suffix_from(max(epoch, 2) // 2, 99.0)
            if not r2.verify_chain_integrity():
                d_local += 1
            if not r2.verify_against_anchor():
                d_anchor += 1
        cadence_detect_local.append(d_local / trials_c)
        cadence_detect_anchor.append(d_anchor / trials_c)

    env = {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine": platform.machine(),
    }

    results = {
        "environment": env,
        "sizes": sizes,
        "local_hash_us_per_decision_mean": local_us,
        "local_hash_us_per_decision_stdev": local_us_stdev,
        "local_ed25519_ms_per_decision_mean": ed25519_ms,
        "local_ed25519_ms_per_decision_stdev": ed25519_stdev,
        "modeled_dual_remote_kms_ms": MODELED_DUAL_KMS_MS,
        "modeled_kms_rtt_ms_each": MODELED_KMS_RTT_MS,
        "modeled_kms_note": "Illustrative RTT model only; NOT measured against AWS/GCP/Azure KMS.",
        "verify_ms_mean": verify_ms,
        "merkle_build_ms_mean": merkle_ms,
        "flat_export_bytes": flat_bytes,
        "selective_bytes": selective_bytes,
        "attack_trials": trials,
        "naive_edit_detected_local": naive_local,
        "suffix_rewrite_detected_local": rewrite_local,
        "suffix_rewrite_detected_anchor": rewrite_anchor,
        "deletion_detected_local": delete_local,
        "deletion_detected_anchor": delete_anchor,
        "epoch_sizes": epoch_sizes,
        "undetectable_rewrite_window_decisions": undetectable_windows,
        "batch_ks": batch_ks,
        "batch_sign_ms_per_decision": batch_ms_per_decision,
        "cadence_detect_rate_local": cadence_detect_local,
        "cadence_detect_rate_vs_prior_anchor": cadence_detect_anchor,
        "cadence_trials_per_epoch": trials_c,
    }
    (out_dir / "benchmark_results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))

    if plt is None:
        return results

    # Fig 1a — constant local hash cost (zoom shows ~4 µs, not empty)
    fig, ax = plt.subplots(figsize=(6.4, 3.7))
    ax.errorbar(sizes, local_us, yerr=local_us_stdev, marker="o", color="#1f4e79", capsize=3)
    ax.set_xlabel("Candidates logged (n)")
    ax.set_ylabel("Latency (µs / decision)")
    ax.set_title("Fig. 1a — Local SHA-256 hashing cost")
    ax.set_ylim(0, max(local_us) * 1.35)
    ax.grid(True, alpha=0.3)
    ax.axhline(statistics.mean(local_us), color="#666", linestyle=":", linewidth=1)
    ax.text(sizes[-1], statistics.mean(local_us) * 1.08, f"mean {statistics.mean(local_us):.2f} µs", ha="right", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_dir / "fig1_log_latency.png", dpi=200)
    plt.close(fig)

    # Fig 1b — log-scale bars so hash / Ed25519 / modeled KMS are ALL visible
    hash_ms = statistics.mean(local_us) / 1000.0  # µs → ms
    ed_ms = statistics.mean(ed25519_ms)
    labels_cost = ["Local SHA-256\nhash only", "Local Ed25519\ndual-sign", "Modeled dual\nremote KMS"]
    vals_cost = [hash_ms, ed_ms, MODELED_DUAL_KMS_MS]
    colors_cost = ["#1f4e79", "#2e7d32", "#c55a11"]
    fig, ax = plt.subplots(figsize=(6.8, 3.9))
    bars = ax.bar(labels_cost, vals_cost, color=colors_cost)
    ax.set_yscale("log")
    ax.set_ylabel("Latency (ms / decision, log scale)")
    ax.set_title("Fig. 1 — Local crypto vs modeled remote KMS")
    ax.grid(True, axis="y", which="both", alpha=0.3)
    for bar, v in zip(bars, vals_cost):
        if v < 0.01:
            label = f"{v*1000:.2f} µs"
        elif v < 1:
            label = f"{v*1000:.0f} µs\n({v:.3f} ms)"
        else:
            label = f"{v:.0f} ms\n(modeled)"
        ax.text(bar.get_x() + bar.get_width() / 2, v * 1.15, label, ha="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_dir / "fig1b_kms_latency.png", dpi=200)
    plt.close(fig)

    # Fig 2: side-by-side panels
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.2, 3.5))
    ax1.plot(sizes, verify_ms, marker="s", color="#1f4e79")
    ax1.set_xlabel("Candidates logged (n)")
    ax1.set_ylabel("Wall time (ms)")
    ax1.set_title("Chain + signature verify")
    ax1.set_ylim(0, max(verify_ms) * 1.15)
    ax1.grid(True, alpha=0.3)
    ax1.text(sizes[-1], verify_ms[-1], f" {verify_ms[-1]:.0f} ms", va="bottom", fontsize=8)

    ax2.plot(sizes, merkle_ms, marker="^", color="#c55a11")
    ax2.set_xlabel("Candidates logged (n)")
    ax2.set_ylabel("Wall time (ms)")
    ax2.set_title("Merkle tree build")
    ax2.set_ylim(0, max(merkle_ms) * 1.2)
    ax2.grid(True, alpha=0.3)
    ax2.text(sizes[-1], merkle_ms[-1], f" {merkle_ms[-1]:.2f} ms", va="bottom", fontsize=8)

    fig.suptitle("Fig. 2 — Offline verification cost", fontsize=11)
    fig.tight_layout()
    fig.savefig(out_dir / "fig2_verify_merkle.png", dpi=200)
    plt.close(fig)

    # Fig 3: side-by-side (not dual-axis overlay)
    flat_kb = [b / 1024 for b in flat_bytes]
    sel_kb = [b / 1024 for b in selective_bytes]
    reduction = [f / s for f, s in zip(flat_kb, sel_kb)]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.4, 3.6))
    ax1.plot(sizes, flat_kb, marker="o", color="#7f7f7f")
    ax1.set_xlabel("Candidates in cohort (n)")
    ax1.set_ylabel("Payload size (KB)")
    ax1.set_title("Full cohort flat export")
    ax1.set_ylim(0, max(flat_kb) * 1.1)
    ax1.grid(True, alpha=0.3)
    ax1.text(sizes[-1], flat_kb[-1], f" {flat_kb[-1]:.0f} KB", va="bottom", fontsize=8)

    ax2.plot(sizes, sel_kb, marker="D", color="#2e7d32")
    ax2.set_xlabel("Candidates in cohort (n)")
    ax2.set_ylabel("Payload size (KB)")
    ax2.set_title("One-candidate Merkle disclosure")
    ax2.set_ylim(0, max(1.5, max(sel_kb) * 1.3))
    ax2.grid(True, alpha=0.3)
    ax2.text(sizes[-1], sel_kb[-1], f" {sel_kb[-1]:.2f} KB", va="bottom", fontsize=8)

    fig.suptitle("Fig. 2 — Disclosure size", fontsize=11)
    fig.tight_layout()
    fig.savefig(out_dir / "fig3_disclosure_size.png", dpi=200)
    plt.close(fig)

    # Fig 3b — ratio (the meaningful comparison metric)
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    ax.plot(sizes, reduction, marker="o", color="#6a1b9a", linewidth=2)
    ax.set_xlabel("Candidates in cohort (n)")
    ax.set_ylabel("How many times smaller? (flat ÷ selective)")
    ax.set_title("Fig. 3b — Flat export vs selective disclosure (size ratio)")
    ax.set_ylim(0, max(reduction) * 1.2)
    ax.grid(True, alpha=0.3)
    for x, y in zip(sizes, reduction):
        ax.text(x, y + max(reduction) * 0.03, f"{y:.0f}×", ha="center", fontsize=9, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out_dir / "fig3b_disclosure_ratio.png", dpi=200)
    plt.close(fig)

    # Fig 4: grouped bars
    attack_names = ["Naïve edit", "Suffix rewrite", "Deletion"]
    local_rates = [naive_local, rewrite_local, delete_local]
    anchor_rates = [trials, rewrite_anchor, delete_anchor]
    x = np.arange(len(attack_names))
    width = 0.35
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    b1 = ax.bar(x - width / 2, local_rates, width, label="Local chain+sig only", color="#c62828")
    b2 = ax.bar(x + width / 2, anchor_rates, width, label="Local + external anchor", color="#2e7d32")
    ax.set_ylabel(f"Detected / {trials} trials")
    ax.set_xticks(x)
    ax.set_xticklabels(attack_names)
    ax.set_ylim(0, trials * 1.28)
    ax.set_title("Fig. 2 — Tamper detection: local checks vs external anchoring")
    ax.legend(fontsize=8, loc="upper right")
    ax.grid(True, axis="y", alpha=0.3)
    for bars in (b1, b2):
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2, h + 2, f"{int(h)}", ha="center", fontsize=9)
    fig.tight_layout()
    fig.savefig(out_dir / "fig4_tamper_detection.png", dpi=200)
    plt.close(fig)

    # Fig 5 — REAL trade-off (not y=x): for 10k decisions/day, anchors/day vs blind window
    DAILY = 10000
    epochs = epoch_sizes
    anchors_per_day = [DAILY / e for e in epochs]
    blind_window = list(epochs)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.6, 3.8))
    ax1.plot(blind_window, anchors_per_day, marker="o", color="#6a1b9a", linewidth=2)
    ax1.set_xscale("log")
    ax1.set_yscale("log")
    ax1.set_xlabel("Max silent-rewrite window (decisions)")
    ax1.set_ylabel("Anchor publishes needed / day\n(assuming 10,000 decisions/day)")
    ax1.set_title("Integrity vs ops cost")
    ax1.grid(True, which="both", alpha=0.3)
    for x, y, e in zip(blind_window, anchors_per_day, epochs):
        if e in (1, 100, 1000):
            ax1.annotate(f"epoch={e}\n{y:.0f} pubs/day", xy=(x, y), textcoords="offset points",
                         xytext=(6, 6), fontsize=7)
    ax2.plot(batch_ks, [y * 1000 for y in batch_ms_per_decision], marker="s", color="#1f4e79", linewidth=2)
    ax2.set_xlabel("Batch size k (sign Merkle root every k decisions)")
    ax2.set_ylabel("Amortized sign cost (µs / decision)")
    ax2.set_title("Batch signing amortization")
    ax2.set_ylim(0, max(y * 1000 for y in batch_ms_per_decision) * 1.25)
    ax2.grid(True, alpha=0.3)
    for x, y in zip(batch_ks, batch_ms_per_decision):
        ax2.text(x, y * 1000 + 5, f"{y*1000:.1f} µs", ha="center", fontsize=8)
    fig.suptitle("Fig. 5 — Operational trade-offs", fontsize=11)
    fig.tight_layout()
    fig.savefig(out_dir / "fig5_tradeoffs.png", dpi=200)
    plt.close(fig)

    # Fig A — clearer architecture with labeled arrows
    from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

    fig, ax = plt.subplots(figsize=(9.0, 4.6))
    ax.set_xlim(0, 12)
    ax.set_ylim(0, 7)
    ax.axis("off")
    ax.set_title("Fig. A — Verifiable Hiring Recorder architecture", fontsize=12, pad=10)

    def box(x, y, w, h, text, color):
        p = FancyBboxPatch(
            (x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.12",
            facecolor=color, edgecolor="#222", linewidth=1.2,
        )
        ax.add_patch(p)
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=8)

    def arrow(x1, y1, x2, y2, label=None):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="->", color="#333", lw=1.4))
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.22, label, ha="center", fontsize=7, color="#444")

    box(0.2, 4.6, 2.3, 1.3, "1. ATS Decision\nService\n(score, threshold,\nmodel version)", "#dbeafe")
    box(3.0, 4.6, 2.5, 1.3, "2. Hash-chain +\nEd25519 dual sign\n(vendor + employer)", "#fef3c7")
    box(6.0, 4.6, 2.3, 1.3, "3. Append-only\nDecision Log\n(WORM-oriented)", "#e5e7eb")
    box(8.8, 4.6, 2.8, 1.3, "4. Merkle tree +\nselective disclosure\n(one-candidate proof)", "#dcfce7")

    box(1.5, 1.8, 2.2, 1.2, "Vendor key\n(KMS / HSM)", "#fee2e2")
    box(4.0, 1.8, 2.2, 1.2, "Employer key\n(KMS / HSM)", "#fee2e2")
    box(6.8, 1.8, 2.4, 1.2, "5. External epoch\nanchor\n(TSA / CT / WORM)", "#f3e8ff")
    box(9.5, 1.8, 2.2, 1.2, "6. Auditor / Court\nverifies proof\n+ anchor root", "#dbeafe")

    arrow(2.5, 5.25, 3.0, 5.25, "decision")
    arrow(5.5, 5.25, 6.0, 5.25, "record")
    arrow(8.3, 5.25, 8.8, 5.25, "leaves")
    arrow(2.6, 3.0, 3.8, 4.6, "sign")
    arrow(5.1, 3.0, 4.5, 4.6, "sign")
    arrow(7.15, 4.6, 8.0, 3.0, "publish root")
    arrow(10.2, 4.6, 10.6, 3.0, "disclose")

    ax.text(
        6.0, 0.45,
        "R1 hash-chain · R2 dual signatures · R3 selective Merkle disclosure · R4 external epoch anchoring",
        ha="center", fontsize=8, style="italic",
    )
    fig.tight_layout()
    fig.savefig(out_dir / "fig0_architecture.png", dpi=200)
    plt.close(fig)

    print(f"Figures written to {out_dir}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bench", action="store_true")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "figures")
    args = parser.parse_args()
    if args.bench:
        run_benchmarks(args.out)
    else:
        demo()


if __name__ == "__main__":
    main()
