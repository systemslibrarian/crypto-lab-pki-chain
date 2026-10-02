import { describe, it, expect } from 'vitest';
import { issuerDescendants } from './pki';
import { runSiblingCompromise, siblingFixture, validateDnsPath } from './siblings';

describe('sibling CA compromise and impersonation', () => {
  for (const constrained of [false, true]) it(`executes impersonation with constraints ${constrained}`, async () => {
    const r = await runSiblingCompromise(constrained);
    expect(r.legitimate.accepted).toBe(true);
    expect(r.own.accepted).toBe(true);
    expect(r.attack.path.ok).toBe(true);
    expect(r.attack.hostnameMatches).toBe(true);
    expect(r.attack.accepted).toBe(!constrained);
    expect(r.attack.namePermitted).toBe(!constrained);
    expect(r.nodes.filter(n => n.keyStolen).map(n => n.subject)).toEqual(['CN=Intermediate A']);
    expect(r.nodes.filter(n => n.inSubtree).map(n => n.subject)).toEqual(['CN=Intermediate A', 'CN=api.a.demo.test']);
  });
  it('binds the constraint into the root signature and checks trust and requested identity', async () => {
    const f = await siblingFixture(true);
    const chain = { root: f.root, intermediate: f.a, leaf: f.forged };
    expect((await validateDnsPath(chain, { trustedRoots: new Set() }, 'api.b.demo.test')).path.ok).toBe(false);
    expect((await validateDnsPath(chain, f.store, 'other.demo.test')).hostnameMatches).toBe(false);
    chain.intermediate = { ...f.a, cert: { ...f.a.cert, permittedDnsSuffix: undefined } };
    const r = await validateDnsPath(chain, f.store, 'api.b.demo.test');
    expect(r.path.steps.find(s => s.label === 'Intermediate signature')?.ok).toBe(false);
    expect(r.accepted).toBe(false);
  });
  it('does not confuse suffixes, and does not accept an expired intermediate', async () => {
    const f = await siblingFixture(true);
    const chain = { root: f.root, intermediate: f.a, leaf: { ...f.forged, cert: { ...f.forged.cert, dnsName: 'evila.demo.test' } } };
    expect((await validateDnsPath(chain, f.store, 'evila.demo.test')).namePermitted).toBe(false);
    chain.intermediate = { ...f.a, cert: { ...f.a.cert, validTo: '2000-01-01T00:00:00.000Z' } };
    expect((await validateDnsPath(chain, f.store, 'evila.demo.test')).intermediateCurrent).toBe(false);
  });
  it('walks both sibling branches from the root and terminates on a self-signed root', async () => {
    const f = await siblingFixture(false);
    const certs = [f.root.cert, f.a.cert, f.b.cert, f.leafA.cert, f.leafB.cert];
    expect(issuerDescendants(certs, f.root.cert.subject).size).toBe(5);
    expect(issuerDescendants(certs, f.b.cert.subject)).toEqual(new Set([f.b.cert.subject, f.leafB.cert.subject]));
    expect(issuerDescendants(certs, null).size).toBe(0);
  });
});
