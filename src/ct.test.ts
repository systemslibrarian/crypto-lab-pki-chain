import { describe, it, expect } from 'vitest';
import { createCtLog } from './ct';
import { createDemoChain, type Certificate } from './pki';

/** Build N distinct certificates by varying one signed field (the serial). */
async function makeCerts(count: number): Promise<Certificate[]> {
  const chain = await createDemoChain();
  return Array.from({ length: count }, (_unused, index) => ({
    ...chain.leaf.cert,
    serialNumber: `${chain.leaf.cert.serialNumber}-${index}`,
  }));
}

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
