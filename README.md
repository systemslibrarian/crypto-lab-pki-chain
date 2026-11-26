# crypto-lab-pki-chain

## What It Is

This browser-native lab demonstrates Public Key Infrastructure (PKI) certificate chain trust using real WebCrypto ECDSA P-256 signatures. A Root CA signs an Intermediate CA certificate, which in turn signs a Leaf certificate; every signature is verified in-browser using `crypto.subtle`. The demo also covers Certificate Transparency (CT) — an append-only Merkle log where certificates are submitted and inclusion proofs are generated and verified using SHA-256. The security model is hierarchical trust: all authenticity flows from one trusted root anchor, and any forged or revoked link invalidates all descendants.

## When to Use It

- **Learning TLS certificate chain validation** — the demo shows how browsers verify each link before trusting a server's identity.
- **Auditing a custom certificate validator** — the tamper and revocation controls expose exactly which checks a validator must pass.
- **Understanding CT monitoring** — useful when building a certificate log monitor or implementing CT client-side verification.
- **Studying CA compromise blast radius** — the intermediate and root compromise scenarios separate valid signatures, policy distrust, stolen keys, and identities an attacker can impersonate.
- When you need peer-to-peer trust without a central authority, prefer web-of-trust or decentralized PKI (e.g., DANE); hierarchical PKI is the wrong model for that.
- Do NOT treat this as a production PKI or certificate validator — it is a browser teaching demo, not a hardened CA or TLS stack.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-pki-chain](https://systemslibrarian.github.io/crypto-lab-pki-chain/)**

The demo provides six interactive exhibits:

1. **The Chain** — inspect the Root → Intermediate → Leaf certificates; selecting a link plays a short **sign / verify** flow showing the issuer's *private* key signing the subject's fields and the issuer's *public* key verifying, making the sign-with-private / verify-with-public asymmetry concrete.
2. **Chain Validation** — real WebCrypto verification of every link. The **Tamper / Repair** buttons toggle a single signed field so you can flip a link between PASS and FAIL; a **cause → effect** panel shows the exact bytes appended to the signed payload and anchor-links to the specific validation step those bytes broke. Revocation evidence is shown separately from the relying-party decision: missing, unknown, and stale results are never green evidence even when the selected fail-open policy accepts the chain. A supplied response with an invalid signer is rejected under either policy. Choose strict policy to require current authenticated good evidence for both non-root certificates.
3. **Trust Stores** — the same cryptographically valid chain accepted or rejected depending on Browser / OS / Application trust roots.
4. **CA Compromise** — mark a CA as compromised and watch its subtree fall. A per-link contrast table shows that **signatures still verify** (the math is untouched) while the affected links are **distrusted by policy** — the opposite of the tamper case, where a signature genuinely fails. A second experiment builds two sibling intermediates and actually signs a certificate for B’s hostname with A’s stolen key. Both the legitimate B path and the forged A path validate without a name constraint; a root-signed DNS constraint on A blocks the forgery while preserving legitimate issuance. See [architecture details](docs/sibling-compromise.md).
5. **Certificate Transparency** — submit certificates to a simulated append-only log and see the **actual RFC 6962 Merkle tree drawn as a node diagram**. Clicking a leaf (or *Inclusion Proof*) highlights the target leaf, lights up exactly the `log₂(n)` audit-path sibling hashes needed to rebuild the root, dims the rest, and shows the recomputed root next to the log's stored root so `verify=true` reads as *these two hashes match*. Consistency proofs and misissuance monitoring run on the same live log.
6. **PQ Migration** — compare classical P-256, ML-DSA, and hybrid post-quantum signature footprints drawn to scale, with each bar tagged **measured** (computed live from this lab's chain) or **reference** (FIPS 204 spec value).

A **Reset lab** button restores every scenario to its defaults, and **CRL** / **OCSP** checkboxes simulate leaf revocation. Exhibit 2 also compares no response, current issuer-signed good responses, an authentic but stale leaf response, and a response signed by the wrong key. The signatures cover fixed-order JSON using WebCrypto ECDSA P-256; these are not RFC 6960 DER messages or a production OCSP client. The response scenario covers both leaf and intermediate certificates; the CRL and revoked status checkboxes remain unsigned teaching inputs. The default fail-open choice illustrates acceptance without positive evidence, not verified non-revocation.

Ordinary submissions issue a new serial and sign it with the demo intermediate CA. An inclusion proof covers the submitted JSON entry. Verifying that proof alone does not validate the certificate or its issuer. The separate monitor checks for an unexpected issuer name.

The Merkle tree hashing follows RFC 6962 §2.1 — leaves prefixed with `0x00`, interior nodes with `0x01`, and trees split at the largest power of two with no lone-node duplication — so inclusion and consistency proofs are the same compact `O(log n)` artifacts a real CT log produces, not a recomputation over the whole log.

## What Can Go Wrong

- **Trust anchor mismatch** — different operating systems and browsers ship different root CA bundles; a certificate trusted by Chrome may be rejected by an embedded application that pins its own trust store.
- **CA compromise blast radius** — key theft does not invalidate existing signatures or reveal descendant private keys. Policy can distrust an issuer’s subtree, but an unconstrained still-trusted issuer can also mint accepted impersonations of names served by a sibling. Signed name constraints must be enforced by the client. This lab implements a DNS-only subset, not complete X.509 path validation.
- **CRL and OCSP freshness** — signed status is only useful when it is current and from an authorized source. A valid signature on an old status does not establish current status. This lab demonstrates the difference with a directly issuer-signed JSON OCSP toy; it does not parse or authenticate CRL files.
- **CT log split-view attack** — a misbehaving log can show different views to different monitors, and verifying proofs does not catch it: inside each view nothing was rewritten, so every inclusion and consistency proof it hands out verifies. Detection comes from comparing signed tree heads across observers; two conflicting heads for one log are the proof of misbehaviour (RFC 6962 §5, §7.3). This lab generates and verifies proofs against one view, so it shows the limit rather than the detection.
- **Signature algorithm confusion** — ECDSA P-256 signatures are tied to the `SHA-256` hash; using a different hash parameter at verification time silently fails rather than throwing in some WebCrypto implementations.

## Real-World Usage

### Certificate issuance: where trust can fail

The [case study near the top of the live lab](https://systemslibrarian.github.io/crypto-lab-pki-chain/#certificate-issuance) connects certificate validation to unauthorized issuance. A client must validate the requested hostname and certificate path, and the server must prove possession of the matching private key. If an attacker obtains an accepted certificate for the target hostname and controls its matching key, intercepted or redirected connections can authenticate the attacker even though the legitimate server's key remains secret.

On October 6, 2026, Google reported that hijacks of the `.gh`, `.sl`, and `.as` registries enabled unauthorized certificates for domains belonging to Google and other organizations. Its report did not attribute the incident to compromised Google systems or wrongdoing by the issuing CAs. The case illustrates how compromised domain-control evidence can undermine otherwise valid signatures. CT monitoring can expose unexpected issuance; revocation and client-side blocking are separate response mechanisms. The lab's stolen-CA-key experiment illustrates a different route to impersonation; it does not reproduce these registry hijacks.

Sources:

- [Dan Goodin, Ars Technica: Hackers obtain counterfeit TLS certificates for Google and other large services (October 6, 2026)](https://arstechnica.com/security/2026/10/hackers-obtain-counterfeit-tls-certificates-for-google-and-other-large-services/).
- [Chrome Secure Web and Networking Team: Chrome's Response to Recent ccTLD Registry Hijacks (October 6, 2026)](https://blog.google/security/chromes-response-to-recent-cctld-registry-hijacks/) — primary incident report.
- [RFC 9846 §4.5.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.5.2) (TLS 1.3; obsoletes RFC 8446, where this was §4.4.3) — TLS proof of private-key possession; [RFC 9525 §6](https://www.rfc-editor.org/rfc/rfc9525.html#section-6) — service-identity verification.
- [How CT works](https://certificate.transparency.dev/howctworks/) — public logs and monitoring.
- [RFC 6960 §§2.2, 2.4 and 4.2.2.1–4.2.2.2 (June 2013)](https://www.rfc-editor.org/rfc/rfc6960) — OCSP good/revoked/unknown, authorized responders and response freshness. A signed response from the direct issuer is one permitted authority case; the lab does not model delegated responder certificate authorization.

### Where these mechanisms are used

- **Let's Encrypt** — its roots are RSA 4096 (ISRG Root X1) and ECDSA P-384 (ISRG Root X2), its active intermediates are ECDSA P-384 or RSA 2048, and a subscriber certificate is issued from the intermediate matching the key the subscriber submitted — RSA 2048, 3072 or 4096, or ECDSA P-256 or P-384 ([certificates](https://letsencrypt.org/certificates/), [integration guide](https://letsencrypt.org/docs/integration-guide/)). It [submits all certificates it issues to CT logs](https://letsencrypt.org/docs/ct-logs/). The two-SCT floor is browser root-programme policy, not a Baseline Requirement: [Chrome](https://googlechrome.github.io/CertificateTransparency/ct_policy.html) and [Apple](https://support.apple.com/en-us/103214) each require SCTs from at least two distinct CT logs for certificates valid 180 days or less (three for longer), while [CA/Browser Forum TLS BR 2.3.1](https://cabforum.org/working-groups/server/baseline-requirements/documents/CA-Browser-Forum-TLS-BR-2.3.1.pdf) defines Precertificates (§7.1.2.9) and permits SCT embedding but does not require logging.
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

- **Chain validation** — a well-formed chain with the default fail-open policy is accepted but its missing revocation evidence is marked inconclusive; tampering any signed field breaks that link's signature; an unknown trust anchor is rejected.
- **Intermediate validity** — genuinely root-signed expired and not-yet-valid intermediates fail the core validator while their signatures and the root/leaf dates still pass. Inclusive `notBefore`/`notAfter` boundaries and a currently valid intermediate pass; a reversed interval fails. All three certificates use one validation instant, with an explicit intermediate date step ([RFC 5280 §6.1.3(a)(2)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3)). This remains the lab's simplified JSON certificate model, not a complete RFC 5280 implementation.
- **Narrow-screen validation** — normal and tampered states fit 320px, 380px and desktop viewports. The signature/trust table retains its columns in a focusable horizontal scroll region; scope identifiers can wrap instead of widening the page.
- **Revocation** — CRL and OCSP revocation each reject the chain. Tests separate missing evidence, unsigned toy good status, current issuer-signed good, signed-but-stale good, and a wrong signer under fail-open and strict policies. Browser checks confirm the learner sees evidence status and policy verdict separately.
- **CA compromise** — root compromise distrusts the whole subtree; intermediate compromise spares the root.
- **RFC 6962 Merkle proofs** — inclusion and consistency proofs verify for every leaf and every `old < new` size up to eight, stay `O(log n)` in size, and are rejected when any root or proof node is corrupted.
- **Drawable tree fidelity** — the tree rendered in Exhibit 5 recomputes to the same root as the log, and the sibling hashes it highlights on the audit path are exactly the RFC 6962 proof hashes — so the visualization can never light up a fabricated path.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*


## Publishing requests

`npm run deploy` requests the existing `pages.yml` workflow at `main`.
The workflow retains its full type, unit, build and browser gates. A successful
request is not evidence of publication; inspect the run and actual public site.
Failed requests retain their nonzero exit status.

## Research scope review — November 2026

Sebastian Paul, Yulia Kuzovkova, Norman Lahr and Ruben Niederhagen, *Mixed Certificate Chains for the Transition to Post-Quantum Authentication in TLS 1.3* (2021), https://eprint.iacr.org/2021/1447: the PQ size comparison is conceptual. Robust dual-signature authentication requires AND verification with message/identity/key binding; OR acceptance fails through a broken component. Mixed certificate chains are a different migration mechanism. Source: https://eprint.iacr.org/2021/1447 (pp. 1–4).

**Standards reviewed 15 November 2026:** RFC 8446 (TLS 1.3) was obsoleted by RFC 9846 in July 2026. The Certificate Verify citation above now points to [RFC 9846 §4.5.2](https://www.rfc-editor.org/rfc/rfc9846.html#section-4.5.2), which carries the same proof-of-possession text that RFC 8446 held in §4.4.3. Source: https://www.rfc-editor.org/info/rfc8446. The Let's Encrypt usage note was rewritten against Let's Encrypt's certificates, integration-guide and CT-logs pages, the Chrome and Apple CT policies, and CA/Browser Forum TLS BR 2.3.1 (4 October 2026): its CA keys are RSA 4096 / ECDSA P-384 (roots) and ECDSA P-384 / RSA 2048 (intermediates), not P-256, and the two-SCT minimum is browser policy rather than a Baseline Requirement.
