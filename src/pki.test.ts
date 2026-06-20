import { describe, it, expect } from 'vitest';
import {
  createDemoChain,
  createTrustStore,
  validateChain,
  createCrl,
  createOcspResponder,
  compromisedSubtree,
  type CertificateChain,
  type TrustStore,
} from './pki';

describe('PKI chain validation', () => {
  it('validates a well-formed chain against its trust anchor', async () => {
    const chain = await createDemoChain();
    const store = await createTrustStore(chain.root.cert);

    const result = await validateChain(chain, store);

    expect(result.ok).toBe(true);
    expect(result.steps.every((step) => step.ok)).toBe(true);
  });

  it('rejects a chain whose root is absent from the trust store', async () => {
    const chain = await createDemoChain();
    const emptyStore: TrustStore = { trustedRoots: new Set<string>() };

    const result = await validateChain(chain, emptyStore);

    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'Trust anchor check')?.ok).toBe(false);
  });

  it('detects tampering: flipping a signed field breaks that link signature', async () => {
    const chain = await createDemoChain();
    const store = await createTrustStore(chain.root.cert);

    // Alter the leaf subject AFTER issuance — the issuer never signed these bytes.
    const tampered: CertificateChain = {
      ...chain,
      leaf: {
        ...chain.leaf,
        cert: { ...chain.leaf.cert, subject: `${chain.leaf.cert.subject} [tampered]` },
      },
    };

    const result = await validateChain(tampered, store);

    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'Leaf signature')?.ok).toBe(false);
  });

  it('honors CRL revocation of the leaf certificate', async () => {
    const chain = await createDemoChain();
    const store = await createTrustStore(chain.root.cert);
    const crl = createCrl(chain.leaf.cert.issuer, [chain.leaf.cert.serialNumber]);

    const result = await validateChain(chain, store, [crl]);

    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'CRL revocation check')?.ok).toBe(false);
  });

  it('honors OCSP revoked status of the leaf certificate', async () => {
    const chain = await createDemoChain();
    const store = await createTrustStore(chain.root.cert);
    const ocsp = createOcspResponder(chain.leaf.cert.issuer, [
      { serialNumber: chain.leaf.cert.serialNumber, status: 'revoked' },
    ]);

    const result = await validateChain(chain, store, [], [ocsp]);

    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.ok).toBe(false);
  });
});

describe('CA compromise blast radius', () => {
  it('root compromise distrusts the entire subtree', async () => {
    const chain = await createDemoChain();
    const distrusted = compromisedSubtree(chain, 'root');

    expect(distrusted.has(chain.root.cert.subject)).toBe(true);
    expect(distrusted.has(chain.intermediate.cert.subject)).toBe(true);
    expect(distrusted.has(chain.leaf.cert.subject)).toBe(true);
  });

  it('intermediate compromise distrusts the leaf but spares the root', async () => {
    const chain = await createDemoChain();
    const distrusted = compromisedSubtree(chain, 'intermediate');

    expect(distrusted.has(chain.root.cert.subject)).toBe(false);
    expect(distrusted.has(chain.intermediate.cert.subject)).toBe(true);
    expect(distrusted.has(chain.leaf.cert.subject)).toBe(true);
  });

  it('no compromise distrusts nothing', async () => {
    const chain = await createDemoChain();

    expect(compromisedSubtree(chain, null).size).toBe(0);
  });
});
