import { describe, it, expect } from 'vitest';
import {
  createDemoChain,
  createTrustStore,
  validateChain,
  createCrl,
  createOcspResponder,
  createSignedOcspResponse,
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
    expect(result.steps.find((step) => step.label === 'CRL revocation check')?.evidence).toBe('missing');
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.evidence).toBe('missing');
    expect(result.steps.find((step) => step.label === 'Revocation evidence policy')?.details).toContain('Fail-open');
  });

  it('rejects missing evidence under a strict policy without claiming revocation', async () => {
    const chain = await createDemoChain();
    const result = await validateChain(chain, await createTrustStore(chain.root.cert), [], [], {
      revocationPolicy: 'require-current-good',
    });
    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.evidence).toBe('missing');
    expect(result.steps.filter((step) => !step.ok).map((step) => step.label)).toEqual(['Revocation evidence policy']);
  });

  it('accepts both current issuer-signed good responses under strict policy', async () => {
    const chain = await createDemoChain();
    const before = new Date(Date.now() - 60_000);
    const after = new Date(Date.now() + 60_000);
    const signed = [
      await createSignedOcspResponse(chain.leaf.cert, chain.intermediate.keyPair.privateKey, 'good', before, after),
      await createSignedOcspResponse(chain.intermediate.cert, chain.root.keyPair.privateKey, 'good', before, after),
    ];
    const result = await validateChain(chain, await createTrustStore(chain.root.cert), [], [], {
      revocationPolicy: 'require-current-good', signedOcspResponses: signed,
    });
    expect(result.ok).toBe(true);
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.evidence).toBe('good');
    expect(result.steps.find((step) => step.label === 'CRL revocation check')?.evidence).toBe('missing');
  });

  it('does not confuse signed-but-stale good with a current good response', async () => {
    const chain = await createDemoChain();
    const signed = [
      await createSignedOcspResponse(chain.leaf.cert, chain.intermediate.keyPair.privateKey, 'good',
        new Date(Date.now() - 172_800_000), new Date(Date.now() - 86_400_000)),
      await createSignedOcspResponse(chain.intermediate.cert, chain.root.keyPair.privateKey, 'good',
        new Date(Date.now() - 60_000), new Date(Date.now() + 60_000)),
    ];
    const result = await validateChain(chain, await createTrustStore(chain.root.cert), [], [], {
      revocationPolicy: 'require-current-good', signedOcspResponses: signed,
    });
    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.evidence).toBe('stale');
  });

  it('does not accept a response signed by the certificate rather than its direct issuer', async () => {
    const chain = await createDemoChain();
    const signed = [await createSignedOcspResponse(chain.leaf.cert, chain.leaf.keyPair.privateKey,
      'good', new Date(Date.now() - 60_000), new Date(Date.now() + 60_000))];
    const result = await validateChain(chain, await createTrustStore(chain.root.cert), [], [], {
      revocationPolicy: 'require-current-good', signedOcspResponses: signed,
    });
    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.evidence).toBe('unauthorized');
  });

  it('rejects an authenticated current revoked status even with fail-open policy', async () => {
    const chain = await createDemoChain();
    const signed = [await createSignedOcspResponse(chain.leaf.cert, chain.intermediate.keyPair.privateKey,
      'revoked', new Date(Date.now() - 60_000), new Date(Date.now() + 60_000))];
    const result = await validateChain(chain, await createTrustStore(chain.root.cert), [], [], {
      signedOcspResponses: signed,
    });
    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.evidence).toBe('revoked');
  });

  it('does not treat unsigned good status maps as authenticated positive evidence', async () => {
    const chain = await createDemoChain();
    const toy = createOcspResponder(chain.leaf.cert.issuer, [
      { serialNumber: chain.leaf.cert.serialNumber, status: 'good' },
    ]);
    const result = await validateChain(chain, await createTrustStore(chain.root.cert), [], [toy], {
      revocationPolicy: 'require-current-good',
    });
    expect(result.ok).toBe(false);
    expect(result.steps.find((step) => step.label === 'OCSP revocation check')?.evidence).toBe('unknown');
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
