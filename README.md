# crypto-lab-pki-chain

## What This Demonstrates

This browser-based lab demonstrates how Public Key Infrastructure (PKI) trust actually works in practice. It walks through certificate chain construction, signature verification, trust-store differences, CA compromise blast radius, and how Certificate Transparency (CT) detects suspicious issuance.

## How It Works

The demo is a Vite + TypeScript single-page app with no backend.

- PKI engine in src/pki.ts generates a Root -> Intermediate -> Leaf chain using real WebCrypto P-256 keys and signatures.
- Chain validation verifies signatures link-by-link, checks trust anchors, and applies CRL/OCSP revocation stubs.
- Compromise simulation marks a CA as compromised and computes all descendants that should be distrusted.
- CT engine in src/ct.ts creates Signed Certificate Timestamps (SCTs), Merkle inclusion proofs, and consistency proofs between tree states using SHA-256.
- UI in src/main.ts renders six interactive exhibits and ties user actions directly to engine outputs.

## Threat Models Covered

- Certificate tampering that breaks signature verification.
- Trust-anchor mismatch across browser, OS, and application trust stores.
- CA compromise causing cascading distrust of issued leaf certificates.
- Misissued certificate detection via Certificate Transparency log monitoring.
- Post-quantum migration risk tradeoffs (classical, ML-DSA, and hybrid transition models).

## Running Locally

```bash
npm install
npm run dev
```

For a production build:

```bash
npm run build
npm run preview
```

## Live Demo

https://systemslibrarian.github.io/crypto-lab-pki-chain/