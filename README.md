[![crypto-lab portfolio](https://img.shields.io/badge/crypto--lab-portfolio-blue?style=flat-square)](https://systemslibrarian.github.io/crypto-lab/)

# crypto-lab-pki-chain

## What It Is

This browser-native lab demonstrates Public Key Infrastructure (PKI) certificate chain trust using real WebCrypto ECDSA P-256 signatures. A Root CA signs an Intermediate CA certificate, which in turn signs a Leaf certificate; every signature is verified in-browser using `crypto.subtle`. The demo also covers Certificate Transparency (CT) — an append-only Merkle log where certificates are submitted and inclusion proofs are generated and verified using SHA-256. The security model is hierarchical trust: all authenticity flows from one trusted root anchor, and any forged or revoked link invalidates all descendants.

## When to Use It

- **Learning TLS certificate chain validation** — the demo shows how browsers verify each link before trusting a server's identity.
- **Auditing a custom certificate validator** — the tamper and revocation controls expose exactly which checks a validator must pass.
- **Understanding CT monitoring** — useful when building a certificate log monitor or implementing CT client-side verification.
- **Studying CA compromise blast radius** — the intermediate and root compromise scenarios show which certificates become invalid when a CA key is stolen.
- **Do not use PKI** when you need peer-to-peer trust without a central authority; web-of-trust or decentralized PKI (e.g., DANE) are better fits for that model.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-pki-chain/](https://systemslibrarian.github.io/crypto-lab-pki-chain/)

The demo provides six interactive exhibits. Use the **Tamper** buttons to corrupt individual certificate fields and watch WebCrypto signature verification fail in real time. Toggle **CRL** and **OCSP** checkboxes to simulate leaf revocation, switch trust store contexts (Browser / OS / Application), mark a CA as compromised to see subtree distrust, submit certificates to the simulated CT log to generate SCTs and Merkle inclusion proofs, and compare classical P-256, ML-DSA, and hybrid post-quantum certificate footprints.

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

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
