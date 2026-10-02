# Sibling CA compromise

The original chain now derives policy reachability using `issuerDescendants` in `src/pki.ts`, a visited-set traversal of issuer links. This handles the root self-loop and multiple sibling branches. Subjects are unique node IDs in the teaching fixture; this is not a general X.509 path builder.

`src/siblings.ts` creates a shared root, two intermediates, and one legitimate DNS leaf per intermediate. Only A's signing capability is given to the attacker. The attacker issues a fresh leaf carrying B's hostname and an attacker-controlled public key. B's private key is never used to sign the forgery.

`validateDnsPath` combines the existing chain checks with an exact requested-hostname match, intermediate validity, and a DNS suffix permission signed into A's certificate by the root. The DNS-only rule allows the suffix itself and dot-delimited subdomains. No constraint means unrestricted issuance. Both legitimate paths are positive controls.

The constraint is serialized into the signed certificate payload. Removing it after issuance breaks the root's signature; changing a UI label cannot remove it. The experiment shows that the forged signature verifies in either case, while the constrained validator rejects B's name. In unconstrained mode both the genuine B certificate and the forged A certificate are accepted by a client trusting the common root, before revocation.

The UI separately reports stolen keys, issuer-subtree membership, signature/path checks, hostname matching, and final identity acceptance. It defaults to constrained issuance, labels unrestricted mode deliberately vulnerable, retires stale results, and participates in Reset lab.

Scope: signed JSON rather than DER, no general NameConstraints implementation, no wildcards/IDNA/IP/email constraints, no TLS handshake, no automatic compromise discovery or historical signature invalidation. `src/siblings.test.ts` checks containment and impersonation, signed-constraint removal, unknown roots, hostname mismatch, suffix boundaries, validity, and traversal. `e2e/claims.spec.ts` checks displayed results and reset. Run `npm test`, `npm run build`, and `npm run test:a11y`.
