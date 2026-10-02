import { createCertificate, createDemoChain, createTrustStore, issuerDescendants, validateChain,
  type CertificateChain, type SignedCertificate, type TrustStore } from './pki';
const generate = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);

/** DNS-only teaching subset, not RFC 5280's general NameConstraints algorithm. */
export async function validateDnsPath(chain: CertificateChain, store: TrustStore, hostname: string) {
  const path = await validateChain(chain, store);
  const dns = chain.leaf.cert.dnsName;
  const suffix = chain.intermediate.cert.permittedDnsSuffix;
  const hostnameMatches = dns === hostname;
  const namePermitted = suffix === undefined || (dns !== undefined && (dns === suffix || dns.endsWith(`.${suffix}`)));
  const now = Date.now();
  const intermediateCurrent = now >= Date.parse(chain.intermediate.cert.validFrom) && now <= Date.parse(chain.intermediate.cert.validTo);
  return { path, hostnameMatches, namePermitted, intermediateCurrent,
    accepted: path.ok && hostnameMatches && namePermitted && intermediateCurrent };
}

export async function siblingFixture(constrained: boolean) {
  const initial = await createDemoChain();
  const root = initial.root;
  const from = new Date(root.cert.validFrom), to = new Date(root.cert.validTo);
  const issue = async (subject: string, issuer: SignedCertificate, names: { dnsName?: string; permittedDnsSuffix?: string } = {}): Promise<SignedCertificate> => {
    const keyPair = await generate();
    const cert = await createCertificate(subject, issuer.cert.subject, keyPair.publicKey, issuer.keyPair.privateKey, from, to, names);
    return { cert, keyPair };
  };
  const a = await issue('CN=Intermediate A', root, constrained ? { permittedDnsSuffix: 'a.demo.test' } : {});
  const b = await issue('CN=Intermediate B', root, { permittedDnsSuffix: 'b.demo.test' });
  const leafA = await issue('CN=api.a.demo.test', a, { dnsName: 'api.a.demo.test' });
  const leafB = await issue('CN=api.b.demo.test', b, { dnsName: 'api.b.demo.test' });
  // Attacker receives A's signing capability, never B's key or the root's key.
  const forged = await issue('CN=api.b.demo.test', a, { dnsName: 'api.b.demo.test' });
  const store = await createTrustStore(root.cert);
  return { root, a, b, leafA, leafB, forged, store };
}

export async function runSiblingCompromise(constrained: boolean) {
  const f = await siblingFixture(constrained);
  const legitimate = await validateDnsPath({ root: f.root, intermediate: f.b, leaf: f.leafB }, f.store, 'api.b.demo.test');
  const own = await validateDnsPath({ root: f.root, intermediate: f.a, leaf: f.leafA }, f.store, 'api.a.demo.test');
  const attack = await validateDnsPath({ root: f.root, intermediate: f.a, leaf: f.forged }, f.store, 'api.b.demo.test');
  const certificates = [f.root.cert, f.a.cert, f.leafA.cert, f.b.cert, f.leafB.cert];
  const descendants = issuerDescendants(certificates, f.a.cert.subject);
  return { legitimate, own, attack, nodes: certificates.map(cert => ({ subject: cert.subject, issuer: cert.issuer,
    keyStolen: cert === f.a.cert, inSubtree: descendants.has(cert.subject) })) };
}
