# crypto-lab-pki-chain

## What It Is

This browser-native lab demonstrates Public Key Infrastructure (PKI) certificate chain trust using real WebCrypto ECDSA P-256 signatures. A Root CA signs an Intermediate CA certificate, which in turn signs a Leaf certificate; every signature is verified in-browser using `crypto.subtle`. The demo also covers Certificate Transparency (CT) — an append-only Merkle log where certificates are submitted and inclusion proofs are generated and verified using SHA-256. The security model is hierarchical trust: all authenticity flows from one trusted root anchor, and any forged or revoked link invalidates all descendants.

## When to Use It

- **Learning TLS certificate chain validation** — the demo shows how browsers verify each link before trusting a server's identity.
- **Auditing a custom certificate validator** — the tamper and revocation controls expose exactly which checks a validator must pass.
- **Understanding CT monitoring** — useful when building a certificate log monitor or implementing CT client-side verification.
- **Studying CA compromise blast radius** — the intermediate and root compromise scenarios show which certificates become invalid when a CA key is stolen.
- When you need peer-to-peer trust without a central authority, prefer web-of-trust or decentralized PKI (e.g., DANE); hierarchical PKI is the wrong model for that.
- Do NOT treat this as a production PKI or certificate validator — it is a browser teaching demo, not a hardened CA or TLS stack.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/)**

The demo provides six interactive exhibits. The **Tamper / Repair** buttons toggle a single signed field on any certificate so you can flip a link between PASS and FAIL and watch WebCrypto signature verification react in real time; a **Reset lab** button restores every scenario to its defaults. Toggle **CRL** and **OCSP** checkboxes to simulate leaf revocation, switch trust store contexts (Browser / OS / Application), mark a CA as compromised to see subtree distrust, submit certificates to the simulated CT log to generate SCTs and verify **RFC 6962 Merkle inclusion and consistency proofs**, and compare classical P-256, ML-DSA, and hybrid post-quantum signature footprints drawn to scale from the live chain.

The Merkle log is implemented to RFC 6962 exactly — leaves prefixed with `0x00`, interior nodes with `0x01`, and trees split at the largest power of two with no lone-node duplication — so inclusion and consistency proofs are the same compact `O(log n)` artifacts a real CT log produces, not a recomputation over the whole log.

## What Can Go Wrong

- **Trust anchor mismatch** — different operating systems and browsers ship different root CA bundles; a certificate trusted by Chrome may be rejected by an embedded application that pins its own trust store.
- **CA compromise blast radius** — if an Intermediate CA private key is stolen, every leaf certificate it ever signed is retroactively untrustworthy, even if the leaf itself was issued correctly.
- **CRL staleness** — certificate revocation lists have a validity window; a revoked certificate may still be accepted if the relying party caches an outdated CRL and the responder is unavailable.
- **CT log split-view attack** — without verifying consistency proofs between two tree states, a misbehaving log can show different views to different monitors, hiding a fraudulent certificate from detection.
- **Signature algorithm confusion** — ECDSA P-256 signatures are tied to the `SHA-256` hash; using a different hash parameter at verification time silently fails rather than throwing in some WebCrypto implementations.

## Real-World Usage

- **Let's Encrypt** — issues certificates using ECDSA P-256 chains and submits every certificate to at least two CT logs as required by the CA/Browser Forum Baseline Requirements.
- **Google Chrome** — has enforced CT inclusion for all publicly trusted TLS certificates since April 2018; connections to sites with certificates not logged in a trusted CT log are rejected.
- **Apple platforms** — Safari and iOS enforce CT policy requiring certificates to include SCTs from at least two approved logs before the TLS handshake is accepted.
- **ACME protocol (RFC 8555)** — the automated certificate issuance protocol used by Let's Encrypt and other CAs encodes the Root → Intermediate → Leaf chain model directly in its order and finalization flow.
- **Mozilla NSS / Firefox** — maintains an independent root CA trust store (distinct from the OS store), demonstrating exactly the trust-store divergence shown in Exhibit 3.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-pki-chain
cd crypto-lab-pki-chain
npm install
npm run dev
```

## Related Demos
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — SHA-256 Merkle trees and inclusion proofs, the data structure behind Certificate Transparency.
- [crypto-lab-web-of-trust](https://systemslibrarian.github.io/crypto-lab-web-of-trust/) — the decentralized PGP trust-graph alternative to hierarchical CA trust.
- [crypto-lab-dilithium-seal](https://systemslibrarian.github.io/crypto-lab-dilithium-seal/) — ML-DSA signatures, the post-quantum option compared against P-256 in this chain.
- [crypto-lab-pq-rotation](https://systemslibrarian.github.io/crypto-lab-pq-rotation/) — hybrid X.509 certificates and the operational PKI migration to post-quantum signatures.
- [crypto-lab-kerberos](https://systemslibrarian.github.io/crypto-lab-kerberos/) — an alternative authentication model based on a trusted ticket-granting authority rather than certificate chains.

## Tests

A cryptography lab should prove its own crypto, so the math is covered by an executable test suite (`src/pki.test.ts`, `src/ct.test.ts`) that runs in CI before every deploy:

- **Chain validation** — a well-formed chain passes; tampering any signed field breaks that link's signature; an unknown trust anchor is rejected.
- **Revocation** — CRL and OCSP revocation each fail the leaf.
- **CA compromise** — root compromise distrusts the whole subtree; intermediate compromise spares the root.
- **RFC 6962 Merkle proofs** — inclusion and consistency proofs verify for every leaf and every `old < new` size up to eight, stay `O(log n)` in size, and are rejected when any root or proof node is corrupted.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
