# Verifiable Hiring Recorder (Anonymous Artifact)

Research prototype accompanying an anonymous ACM FAccT submission on tamper-evident audit architecture for AI employment screening.

## Scope (honest)

| Property | Status |
|----------|--------|
| Detect naïve log edits | Yes (local chain + Ed25519) |
| Detect privileged suffix rewrite / deletion | Only with **external epoch-root anchor** |
| Prove fairness / non-discrimination | **No** |
| Production KMS latency | **Modeled**, not measured against cloud KMS |
| Real digital signatures | **Yes** — Ed25519 (local); remote KMS is modeled separately |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python verifiable_hiring.py
python verifiable_hiring.py --bench
pytest -q
```

## Threat model summary

- **Careless admin**: edits a field, forgets to re-hash → detected locally.
- **Privileged insider with signing keys**: rebuilds suffix or deletes records → local chain still verifies; external anchor detects root drift.
- **Joint DB + anchor custody compromise**: out of scope / requires independent custody assumptions.
- **Fairness adversary** who biases features without log edits: out of scope.

## License

MIT
