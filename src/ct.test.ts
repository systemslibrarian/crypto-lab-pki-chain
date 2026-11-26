import { describe, it, expect } from 'vitest';
import { createCtLog, issueLogCertificate } from './ct';
import { createDemoChain, createTrustStore, validateChain, type Certificate } from './pki';

async function makeCerts(count: number): Promise<Certificate[]> {
  const chain = await createDemoChain();
  return Promise.all(Array.from({ length: count }, () => issueLogCertificate(chain)));
}

it('logs distinct serials carrying valid issuer signatures, including their signed DNS fields', async () => {
  const chain = await createDemoChain();
  chain.leaf.cert.dnsName = 'library.example';
  const store = await createTrustStore(chain.root.cert);
  const certs = await Promise.all([issueLogCertificate(chain), issueLogCertificate(chain)]);
  expect(certs[0].serialNumber).not.toBe(certs[1].serialNumber);
  const log = await createCtLog();
  for (const cert of certs) {
    const result = await validateChain({ ...chain, leaf: { ...chain.leaf, cert } }, store);
    expect(result.steps.find(step => step.label === 'Leaf signature')?.ok).toBe(true);
    expect(cert.dnsName).toBe('library.example');
    const receipt = await log.submitCertificate(cert);
    const bytes = new TextEncoder().encode(JSON.stringify({
      subject: cert.subject, issuer: cert.issuer, publicKey: cert.publicKey,
      validFrom: cert.validFrom, validTo: cert.validTo, serialNumber: cert.serialNumber,
      dnsName: cert.dnsName, permittedDnsSuffix: cert.permittedDnsSuffix,
      signature: Array.from(new Uint8Array(cert.signature), byte => byte.toString(16).padStart(2, '0')).join(''),
    }));
    const leafInput = new Uint8Array(bytes.length + 1);
    leafInput.set(bytes, 1);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', leafInput));
    expect(receipt.entryHash).toBe(Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join(''));
  }
});

/** Flip the first hex nibble so the value always changes, staying valid hex. */
function corrupt(hex: string): string {
  const first = hex[0] === '0' ? '1' : '0';
  return `${first}${hex.slice(1)}`;
}

describe('CT Merkle inclusion proofs (RFC 6962)', () => {
  it('verifies a compact inclusion proof for every leaf at sizes 1..8', async () => {
    for (let n = 1; n <= 8; n += 1) {
      const log = await createCtLog();
      for (const cert of await makeCerts(n)) {
        await log.submitCertificate(cert);
      }

      for (let i = 0; i < n; i += 1) {
        const proof = await log.generateInclusionProof(i);
        expect(await log.verifyInclusionProof(proof)).toBe(true);
        // The proof carries only O(log n) sibling hashes — never the whole log.
        expect(proof.auditPath.length).toBeLessThanOrEqual(Math.ceil(Math.log2(Math.max(2, n))));
      }
    }
  });

  it('rejects an inclusion proof with a corrupted root hash', async () => {
    const log = await createCtLog();
    for (const cert of await makeCerts(5)) {
      await log.submitCertificate(cert);
    }

    const proof = await log.generateInclusionProof(2);
    expect(await log.verifyInclusionProof({ ...proof, rootHash: corrupt(proof.rootHash) })).toBe(false);
  });

  it('rejects an inclusion proof with a corrupted audit-path node', async () => {
    const log = await createCtLog();
    for (const cert of await makeCerts(5)) {
      await log.submitCertificate(cert);
    }

    const proof = await log.generateInclusionProof(2);
    expect(proof.auditPath.length).toBeGreaterThan(0);
    const auditPath = proof.auditPath.map((step, index) =>
      index === 0 ? { ...step, hash: corrupt(step.hash) } : step,
    );
    expect(await log.verifyInclusionProof({ ...proof, auditPath })).toBe(false);
  });
});

describe('CT consistency proofs (RFC 6962)', () => {
  it('verifies a compact consistency proof for every old<new pair up to size 8', async () => {
    for (let n = 2; n <= 8; n += 1) {
      const log = await createCtLog();
      for (const cert of await makeCerts(n)) {
        await log.submitCertificate(cert);
      }

      for (let m = 1; m < n; m += 1) {
        const proof = await log.generateConsistencyProof(m, n);
        expect(await log.verifyConsistencyProof(proof)).toBe(true);
        // The whole point of CT: append-only-ness is provable without the full log.
        expect(proof.proof.length).toBeLessThan(n);
        expect(proof.proof.length).toBeLessThanOrEqual(Math.ceil(Math.log2(n)) + 1);
      }
    }
  });

  it('rejects a consistency proof when the new root is wrong', async () => {
    const log = await createCtLog();
    for (const cert of await makeCerts(6)) {
      await log.submitCertificate(cert);
    }

    const proof = await log.generateConsistencyProof(3, 6);
    expect(await log.verifyConsistencyProof({ ...proof, newRoot: corrupt(proof.newRoot) })).toBe(false);
  });

  it('rejects a consistency proof with a corrupted path node', async () => {
    const log = await createCtLog();
    for (const cert of await makeCerts(7)) {
      await log.submitCertificate(cert);
    }

    const proof = await log.generateConsistencyProof(3, 7);
    const path = proof.proof.map((hash, index) => (index === 0 ? corrupt(hash) : hash));
    expect(await log.verifyConsistencyProof({ ...proof, proof: path })).toBe(false);
  });
});

describe('what the proofs do NOT catch: a split view (RFC 6962 §5, §7.3)', () => {
  it('hands each observer proofs that verify, so only comparing tree heads catches it', async () => {
    // A log that keeps two histories rewrites nothing inside either one, so
    // every proof it issues from either view verifies. The page used to say a
    // log "cannot hide a certificate or fork its view without producing a
    // proof that fails to verify"; this is the counter-example.
    const certs = await makeCerts(5);
    const shared = certs.slice(0, 3);

    const viewA = await createCtLog();
    const viewB = await createCtLog();
    for (const cert of shared) {
      await viewA.submitCertificate(cert);
      await viewB.submitCertificate(cert);
    }
    // Up to the fork point the two views are indistinguishable.
    const anchor = await viewA.rootHash(3);
    expect(await viewB.rootHash(3)).toBe(anchor);

    // Now they diverge: each observer is shown a different fourth entry.
    await viewA.submitCertificate(certs[3]);
    await viewB.submitCertificate(certs[4]);

    for (const view of [viewA, viewB]) {
      // Inclusion of the entry that observer was shown: verifies.
      const inclusion = await view.generateInclusionProof(3);
      expect(await view.verifyInclusionProof(inclusion)).toBe(true);
      // Append-only against the head it anchored before the fork: verifies.
      const consistency = await view.generateConsistencyProof(3, 4);
      expect(await view.verifyConsistencyProof(consistency)).toBe(true);
      expect(consistency.oldRoot).toBe(anchor);
    }

    // Nothing local detected the fork. The two signed tree heads for the same
    // tree size differ, and that comparison — between observers — is the whole
    // detection mechanism.
    expect(await viewA.rootHash(4)).not.toBe(await viewB.rootHash(4));
  });
});

describe('CT drawable tree layout (Exhibit 5 visualization)', () => {
  it('treeLayout root hash equals the log root and spans the whole leaf set', async () => {
    for (let n = 1; n <= 8; n += 1) {
      const log = await createCtLog();
      for (const cert of await makeCerts(n)) {
        await log.submitCertificate(cert);
      }
      const tree = await log.treeLayout();
      expect(tree.hash).toBe(await log.rootHash());
      expect(tree.span).toEqual([0, n - 1]);
    }
  });

  it('audit-path siblings drawn on the tree are exactly the RFC 6962 proof hashes', async () => {
    // Walk the drawable tree the same way the UI highlights it, and confirm the
    // sibling hashes collected equal the audit path — the visualization lights up
    // the real proof, never a fabricated set.
    for (let n = 2; n <= 8; n += 1) {
      const log = await createCtLog();
      for (const cert of await makeCerts(n)) {
        await log.submitCertificate(cert);
      }
      const tree = await log.treeLayout();

      for (let leaf = 0; leaf < n; leaf += 1) {
        const proof = await log.generateInclusionProof(leaf);
        const siblingHashes: string[] = [];
        let node = tree;
        while (!node.isLeaf) {
          const [left, right] = node.children;
          if (leaf <= left.span[1]) {
            siblingHashes.push(right.hash);
            node = left;
          } else {
            siblingHashes.push(left.hash);
            node = right;
          }
        }
        // Audit path is leaf→root; the walk collects root→leaf, so compare as sets.
        expect(new Set(siblingHashes)).toEqual(new Set(proof.auditPath.map((s) => s.hash)));
        expect(siblingHashes.length).toBe(proof.auditPath.length);
      }
    }
  });
});

describe('CT SCT minting and misissuance monitoring', () => {
  it('mints an ECDSA P-256 SCT and flags out-of-policy issuers', async () => {
    const log = await createCtLog();
    const [cert] = await makeCerts(1);
    expect(cert).toBeDefined();

    const sct = await log.submitCertificate(cert!);
    expect(sct.algorithm).toBe('ECDSA_P256_SHA256');
    expect(sct.entryHash).toMatch(/^[0-9a-f]{64}$/);

    const clean = log.detectMisissuance(cert!, new Set([cert!.issuer]));
    expect(clean.suspicious).toBe(false);

    const forged: Certificate = { ...cert!, issuer: 'CN=Rogue CA' };
    const flagged = log.detectMisissuance(forged, new Set([cert!.issuer]));
    expect(flagged.suspicious).toBe(true);
  });
});
