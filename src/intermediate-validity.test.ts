import { afterEach, describe, expect, it, vi } from 'vitest';
import { createCertificate, createDemoChain, createTrustStore, validateChain } from './pki';

describe('core intermediate validity with genuine issuer signatures', () => {
  afterEach(() => vi.useRealTimers());
  const now = '2030-06-15T12:00:00.000Z';
  const cases = [
    ['expired', '2029-01-01T00:00:00Z', '2030-06-15T11:59:59.999Z', false],
    ['not yet valid', '2030-06-15T12:00:00.001Z', '2031-01-01T00:00:00Z', false],
    ['at inclusive notBefore', now, '2031-01-01T00:00:00Z', true],
    ['at inclusive notAfter', '2029-01-01T00:00:00Z', now, true],
    ['within interval', '2029-01-01T00:00:00Z', '2031-01-01T00:00:00Z', true],
    ['reversed interval', '2031-01-01T00:00:00Z', '2029-01-01T00:00:00Z', false],
  ] as const;

  it.each(cases)('%s', async (_name, from, to, accepted) => {
    // Freeze only Date; real WebCrypto signing and verification still execute.
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(new Date(now));
    const chain = await createDemoChain();
    const store = await createTrustStore(chain.root.cert);
    const intermediate = chain.intermediate;
    intermediate.cert = await createCertificate(
      intermediate.cert.subject, chain.root.cert.subject,
      intermediate.keyPair.publicKey, chain.root.keyPair.privateKey,
      new Date(from), new Date(to),
    );
    const result = await validateChain(chain, store);
    expect(result.steps.find(s => s.label === 'Intermediate signature')?.ok).toBe(true);
    expect(result.steps.find(s => s.label === 'Root validity window')?.ok).toBe(true);
    expect(result.steps.find(s => s.label === 'Leaf validity window')?.ok).toBe(true);
    expect(result.ok).toBe(accepted);
    expect(result.steps.find(s => s.label === 'Intermediate validity window')?.ok).toBe(accepted);
    expect(result.steps.filter(s => !s.ok).map(s => s.label))
      .toEqual(accepted ? [] : ['Intermediate validity window']);
  });
});
