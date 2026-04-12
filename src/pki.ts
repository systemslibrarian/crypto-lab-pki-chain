export interface Certificate {
  subject: string;
  issuer: string;
  publicKey: JsonWebKey;
  signature: ArrayBuffer;
  validFrom: string;
  validTo: string;
  serialNumber: string;
}

export interface SignedCertificate {
  cert: Certificate;
  keyPair: CryptoKeyPair;
}

export interface CertificateChain {
  root: SignedCertificate;
  intermediate: SignedCertificate;
  leaf: SignedCertificate;
}

export interface TrustStore {
  trustedRoots: Set<string>;
}

export interface Crl {
  issuer: string;
  revokedSerialNumbers: Set<string>;
}

export type OcspStatus = 'good' | 'revoked' | 'unknown';

export interface OcspResponder {
  issuer: string;
  statusBySerial: Map<string, OcspStatus>;
}

export interface ValidationStep {
  label: string;
  ok: boolean;
  details: string;
}

export interface ValidationResult {
  ok: boolean;
  steps: ValidationStep[];
}

export type CompromisedCa = 'root' | 'intermediate';

const SIGN_ALGO: EcKeyGenParams = {
  name: 'ECDSA',
  namedCurve: 'P-256',
};

const SIGN_PARAMS: EcdsaParams = {
  name: 'ECDSA',
  hash: 'SHA-256',
};

function randomSerial(): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function b64UrlEncode(input: ArrayBuffer): string {
  const bytes = new Uint8Array(input);
  let binary = '';
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function certToBeSigned(cert: Omit<Certificate, 'signature'>): string {
  // Deterministic field order is used to produce stable signature input.
  return JSON.stringify({
    subject: cert.subject,
    issuer: cert.issuer,
    publicKey: cert.publicKey,
    validFrom: cert.validFrom,
    validTo: cert.validTo,
    serialNumber: cert.serialNumber,
  });
}

async function signCertificate(
  unsignedCert: Omit<Certificate, 'signature'>,
  issuerPrivateKey: CryptoKey,
): Promise<Certificate> {
  const payload = new TextEncoder().encode(certToBeSigned(unsignedCert));
  const signature = await crypto.subtle.sign(SIGN_PARAMS, issuerPrivateKey, payload);
  return {
    ...unsignedCert,
    signature,
  };
}

async function verifyCertificateSignature(
  cert: Certificate,
  issuerPublicKey: CryptoKey,
): Promise<boolean> {
  const payload = new TextEncoder().encode(
    certToBeSigned({
      subject: cert.subject,
      issuer: cert.issuer,
      publicKey: cert.publicKey,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      serialNumber: cert.serialNumber,
    }),
  );

  return crypto.subtle.verify(SIGN_PARAMS, issuerPublicKey, cert.signature, payload);
}

function isWithinValidityWindow(cert: Certificate, at: Date = new Date()): boolean {
  const from = new Date(cert.validFrom);
  const to = new Date(cert.validTo);
  return at >= from && at <= to;
}

async function createCertificate(
  subject: string,
  issuer: string,
  subjectPublicKey: CryptoKey,
  issuerPrivateKey: CryptoKey,
  validFrom: Date,
  validTo: Date,
): Promise<Certificate> {
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', subjectPublicKey);
  return signCertificate(
    {
      subject,
      issuer,
      publicKey: publicKeyJwk,
      validFrom: validFrom.toISOString(),
      validTo: validTo.toISOString(),
      serialNumber: randomSerial(),
    },
    issuerPrivateKey,
  );
}

function addStep(steps: ValidationStep[], label: string, ok: boolean, details: string): void {
  steps.push({ label, ok, details });
}

export async function createDemoChain(): Promise<CertificateChain> {
  const now = new Date();
  const oneYear = new Date(now);
  oneYear.setFullYear(now.getFullYear() + 1);

  const rootKeys = await crypto.subtle.generateKey(SIGN_ALGO, true, ['sign', 'verify']);
  const intKeys = await crypto.subtle.generateKey(SIGN_ALGO, true, ['sign', 'verify']);
  const leafKeys = await crypto.subtle.generateKey(SIGN_ALGO, true, ['sign', 'verify']);

  const rootCert = await createCertificate(
    'CN=Crypto Lab Root CA',
    'CN=Crypto Lab Root CA',
    rootKeys.publicKey,
    rootKeys.privateKey,
    now,
    oneYear,
  );

  const intermediateCert = await createCertificate(
    'CN=Crypto Lab Intermediate CA',
    rootCert.subject,
    intKeys.publicKey,
    rootKeys.privateKey,
    now,
    oneYear,
  );

  const leafCert = await createCertificate(
    'CN=demo.crypto-lab.local',
    intermediateCert.subject,
    leafKeys.publicKey,
    intKeys.privateKey,
    now,
    oneYear,
  );

  return {
    root: {
      cert: rootCert,
      keyPair: rootKeys,
    },
    intermediate: {
      cert: intermediateCert,
      keyPair: intKeys,
    },
    leaf: {
      cert: leafCert,
      keyPair: leafKeys,
    },
  };
}

export async function createTrustStore(rootCert: Certificate): Promise<TrustStore> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(certToBeSigned({ ...rootCert, signature: undefined as never } as Omit<
      Certificate,
      'signature'
    >)),
  );

  return {
    trustedRoots: new Set([b64UrlEncode(digest)]),
  };
}

export async function trustAnchorFingerprint(rootCert: Certificate): Promise<string> {
  const payload = new TextEncoder().encode(
    certToBeSigned({
      subject: rootCert.subject,
      issuer: rootCert.issuer,
      publicKey: rootCert.publicKey,
      validFrom: rootCert.validFrom,
      validTo: rootCert.validTo,
      serialNumber: rootCert.serialNumber,
    }),
  );
  const digest = await crypto.subtle.digest('SHA-256', payload);
  return b64UrlEncode(digest);
}

export async function validateChain(
  chain: CertificateChain,
  trustStore: TrustStore,
  crls: Crl[] = [],
  ocspResponders: OcspResponder[] = [],
): Promise<ValidationResult> {
  const steps: ValidationStep[] = [];

  const rootWithinDate = isWithinValidityWindow(chain.root.cert);
  addStep(
    steps,
    'Root validity window',
    rootWithinDate,
    rootWithinDate ? 'Root certificate is within validity period.' : 'Root certificate is expired or not yet valid.',
  );

  const rootSelfSig = await verifyCertificateSignature(chain.root.cert, chain.root.keyPair.publicKey);
  addStep(
    steps,
    'Root self-signature',
    rootSelfSig,
    rootSelfSig ? 'Root self-signature verifies.' : 'Root self-signature verification failed.',
  );

  const interIssuerMatch = chain.intermediate.cert.issuer === chain.root.cert.subject;
  addStep(
    steps,
    'Intermediate issuer linkage',
    interIssuerMatch,
    interIssuerMatch
      ? 'Intermediate issuer matches root subject.'
      : 'Intermediate issuer does not match root subject.',
  );

  const interSig = await verifyCertificateSignature(
    chain.intermediate.cert,
    chain.root.keyPair.publicKey,
  );
  addStep(
    steps,
    'Intermediate signature',
    interSig,
    interSig ? 'Intermediate certificate signature verifies against root key.' : 'Intermediate signature is invalid.',
  );

  const leafIssuerMatch = chain.leaf.cert.issuer === chain.intermediate.cert.subject;
  addStep(
    steps,
    'Leaf issuer linkage',
    leafIssuerMatch,
    leafIssuerMatch
      ? 'Leaf issuer matches intermediate subject.'
      : 'Leaf issuer does not match intermediate subject.',
  );

  const leafSig = await verifyCertificateSignature(chain.leaf.cert, chain.intermediate.keyPair.publicKey);
  addStep(
    steps,
    'Leaf signature',
    leafSig,
    leafSig ? 'Leaf certificate signature verifies against intermediate key.' : 'Leaf signature is invalid.',
  );

  const leafWithinDate = isWithinValidityWindow(chain.leaf.cert);
  addStep(
    steps,
    'Leaf validity window',
    leafWithinDate,
    leafWithinDate ? 'Leaf certificate is within validity period.' : 'Leaf certificate is expired or not yet valid.',
  );

  const rootFp = await trustAnchorFingerprint(chain.root.cert);
  const trusted = trustStore.trustedRoots.has(rootFp);
  addStep(
    steps,
    'Trust anchor check',
    trusted,
    trusted ? 'Root certificate exists in selected trust store.' : 'Root certificate is missing from trust store.',
  );

  const revokedByCrl = isRevokedByCrl(chain.leaf.cert, crls) || isRevokedByCrl(chain.intermediate.cert, crls);
  addStep(
    steps,
    'CRL revocation check',
    !revokedByCrl,
    revokedByCrl ? 'A certificate serial appears in a CRL.' : 'No certificate serial present in supplied CRLs.',
  );

  const ocspLeaf = ocspStatus(chain.leaf.cert, ocspResponders);
  const ocspIntermediate = ocspStatus(chain.intermediate.cert, ocspResponders);
  const ocspGood = ocspLeaf !== 'revoked' && ocspIntermediate !== 'revoked';
  addStep(
    steps,
    'OCSP revocation check',
    ocspGood,
    ocspGood
      ? `OCSP statuses: leaf=${ocspLeaf}, intermediate=${ocspIntermediate}.`
      : `OCSP revoked status detected: leaf=${ocspLeaf}, intermediate=${ocspIntermediate}.`,
  );

  return {
    ok: steps.every((step) => step.ok),
    steps,
  };
}

export function createCrl(issuer: string, revokedSerialNumbers: string[] = []): Crl {
  return {
    issuer,
    revokedSerialNumbers: new Set(revokedSerialNumbers),
  };
}

export function createOcspResponder(
  issuer: string,
  statuses: Array<{ serialNumber: string; status: OcspStatus }> = [],
): OcspResponder {
  return {
    issuer,
    statusBySerial: new Map(statuses.map((row) => [row.serialNumber, row.status])),
  };
}

export function isRevokedByCrl(cert: Certificate, crls: Crl[]): boolean {
  for (const crl of crls) {
    if (crl.issuer === cert.issuer && crl.revokedSerialNumbers.has(cert.serialNumber)) {
      return true;
    }
  }
  return false;
}

export function ocspStatus(cert: Certificate, responders: OcspResponder[]): OcspStatus {
  for (const responder of responders) {
    if (responder.issuer === cert.issuer) {
      return responder.statusBySerial.get(cert.serialNumber) ?? 'unknown';
    }
  }
  return 'unknown';
}

export function compromisedSubtree(
  chain: CertificateChain,
  compromisedCa: CompromisedCa | null,
): Set<string> {
  const untrusted = new Set<string>();

  if (!compromisedCa) {
    return untrusted;
  }

  if (compromisedCa === 'root') {
    untrusted.add(chain.root.cert.subject);
    untrusted.add(chain.intermediate.cert.subject);
    untrusted.add(chain.leaf.cert.subject);
    return untrusted;
  }

  untrusted.add(chain.intermediate.cert.subject);
  untrusted.add(chain.leaf.cert.subject);
  return untrusted;
}
