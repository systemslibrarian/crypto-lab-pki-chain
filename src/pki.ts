export interface Certificate {
  subject: string;
  issuer: string;
  publicKey: JsonWebKey;
  signature: ArrayBuffer;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  dnsName?: string;
  permittedDnsSuffix?: string;
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

/** A deliberately small issuer-signed JSON response, not an RFC 6960 ASN.1 response. */
export interface SignedOcspResponse {
  issuer: string;
  serialNumber: string;
  status: OcspStatus;
  thisUpdate: string;
  nextUpdate: string;
  signature: ArrayBuffer;
}

export type RevocationPolicy = 'allow-unknown' | 'require-current-good';
export type EvidenceState = 'passed' | 'failed' | 'good' | 'revoked' | 'missing' | 'unknown' | 'stale' | 'unauthorized';

export interface ValidationOptions {
  revocationPolicy?: RevocationPolicy;
  signedOcspResponses?: SignedOcspResponse[];
}

export interface ValidationStep {
  label: string;
  /** Whether this step permits the chain under the selected policy. */
  ok: boolean;
  /** What the demonstration actually observed, independently of policy. */
  evidence: EvidenceState;
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
    dnsName: cert.dnsName,
    permittedDnsSuffix: cert.permittedDnsSuffix,
  });
}

function unsignedCertificatePayload(cert: Certificate): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(
    certToBeSigned({
      subject: cert.subject,
      issuer: cert.issuer,
      publicKey: cert.publicKey,
      validFrom: cert.validFrom,
      validTo: cert.validTo,
      serialNumber: cert.serialNumber,
      dnsName: cert.dnsName,
      permittedDnsSuffix: cert.permittedDnsSuffix,
    }),
  );
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
  const payload = unsignedCertificatePayload(cert);

  return crypto.subtle.verify(SIGN_PARAMS, issuerPublicKey, cert.signature, payload);
}

function isWithinValidityWindow(cert: Certificate, at: Date = new Date()): boolean {
  const from = new Date(cert.validFrom);
  const to = new Date(cert.validTo);
  return at >= from && at <= to;
}

export async function createCertificate(
  subject: string,
  issuer: string,
  subjectPublicKey: CryptoKey,
  issuerPrivateKey: CryptoKey,
  validFrom: Date,
  validTo: Date,
  names: { dnsName?: string; permittedDnsSuffix?: string } = {},
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
      ...names,
    },
    issuerPrivateKey,
  );
}

function addStep(
  steps: ValidationStep[], label: string, ok: boolean, details: string,
  evidence: EvidenceState = ok ? 'passed' : 'failed',
): void {
  steps.push({ label, ok, evidence, details });
}

function ocspPayload(response: Omit<SignedOcspResponse, 'signature'>): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify({
    issuer: response.issuer,
    serialNumber: response.serialNumber,
    status: response.status,
    thisUpdate: response.thisUpdate,
    nextUpdate: response.nextUpdate,
  }));
}

export async function createSignedOcspResponse(
  cert: Certificate,
  issuerPrivateKey: CryptoKey,
  status: OcspStatus,
  thisUpdate: Date,
  nextUpdate: Date,
): Promise<SignedOcspResponse> {
  const response = {
    issuer: cert.issuer,
    serialNumber: cert.serialNumber,
    status,
    thisUpdate: thisUpdate.toISOString(),
    nextUpdate: nextUpdate.toISOString(),
  };
  return { ...response, signature: await crypto.subtle.sign(SIGN_PARAMS, issuerPrivateKey, ocspPayload(response)) };
}

type CertificateEvidence = 'good' | 'revoked' | 'missing' | 'unknown' | 'stale' | 'unauthorized';

async function signedOcspEvidence(
  cert: Certificate,
  issuerPublicKey: CryptoKey,
  responses: SignedOcspResponse[],
  at: Date,
): Promise<CertificateEvidence> {
  const response = responses.find((item) => item.issuer === cert.issuer && item.serialNumber === cert.serialNumber);
  if (!response) return 'missing';

  // Only the direct issuer key is authorized in this teaching subset; delegated
  // responders need the additional authorization checks described in RFC 6960.
  const authentic = await crypto.subtle.verify(
    SIGN_PARAMS, issuerPublicKey, response.signature, ocspPayload(response),
  ).catch(() => false);
  if (!authentic) return 'unauthorized';

  const from = Date.parse(response.thisUpdate);
  const until = Date.parse(response.nextUpdate);
  if (!Number.isFinite(from) || !Number.isFinite(until) || from >= until || at.getTime() < from || at.getTime() > until) {
    return 'stale';
  }
  return response.status;
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
  const digest = await crypto.subtle.digest('SHA-256', unsignedCertificatePayload(rootCert));

  return {
    trustedRoots: new Set([b64UrlEncode(digest)]),
  };
}

export async function trustAnchorFingerprint(rootCert: Certificate): Promise<string> {
  const payload = unsignedCertificatePayload(rootCert);
  const digest = await crypto.subtle.digest('SHA-256', payload);
  return b64UrlEncode(digest);
}

export async function validateChain(
  chain: CertificateChain,
  trustStore: TrustStore,
  crls: Crl[] = [],
  ocspResponders: OcspResponder[] = [],
  options: ValidationOptions = {},
): Promise<ValidationResult> {
  const steps: ValidationStep[] = [];
  // Evaluate every certificate against one validation instant.
  const at = new Date();

  const rootWithinDate = isWithinValidityWindow(chain.root.cert, at);
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

  const interWithinDate = isWithinValidityWindow(chain.intermediate.cert, at);
  addStep(
    steps,
    'Intermediate validity window',
    interWithinDate,
    interWithinDate
      ? 'Intermediate certificate is within validity period.'
      : 'Intermediate certificate is expired or not yet valid.',
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

  const leafWithinDate = isWithinValidityWindow(chain.leaf.cert, at);
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

  const policy = options.revocationPolicy ?? 'allow-unknown';
  const revokedByCrl = isRevokedByCrl(chain.leaf.cert, crls) || isRevokedByCrl(chain.intermediate.cert, crls);
  const crlEvidence: EvidenceState = revokedByCrl
    ? 'revoked'
    : crls.some((crl) => crl.issuer === chain.leaf.cert.issuer || crl.issuer === chain.intermediate.cert.issuer)
      ? 'unknown' : 'missing';
  addStep(
    steps,
    'CRL revocation check',
    !revokedByCrl,
    revokedByCrl
      ? 'A serial appears in the supplied toy CRL; reject it.'
      : crlEvidence === 'missing'
        ? 'No CRL supplied. Revocation evidence is missing; absence is not proof of good status.'
        : 'The unsigned toy CRL does not prove current, authenticated non-revocation.',
    crlEvidence,
  );

  const signed = options.signedOcspResponses ?? [];
  const evidenceFor = async (cert: Certificate, issuerPublicKey: CryptoKey): Promise<CertificateEvidence> => {
    const toyStatus = ocspStatus(cert, ocspResponders);
    // A supplied revoked toy indicator remains a conservative rejection even
    // if another scenario supplied a conflicting signed good status.
    if (toyStatus === 'revoked') return 'revoked';
    const signedEvidence = await signedOcspEvidence(cert, issuerPublicKey, signed, at);
    if (signedEvidence !== 'missing') return signedEvidence;
    // An unsigned status map cannot serve as authenticated positive evidence.
    return ocspResponders.some((r) => r.issuer === cert.issuer) ? 'unknown' : 'missing';
  };
  const ocspLeaf = await evidenceFor(chain.leaf.cert, chain.intermediate.keyPair.publicKey);
  const ocspIntermediate = await evidenceFor(chain.intermediate.cert, chain.root.keyPair.publicKey);
  const ocspRevoked = ocspLeaf === 'revoked' || ocspIntermediate === 'revoked';
  const ocspEvidence: EvidenceState = ocspRevoked ? 'revoked'
    : ocspLeaf === 'good' && ocspIntermediate === 'good' ? 'good'
      : ocspLeaf === 'unauthorized' || ocspIntermediate === 'unauthorized' ? 'unauthorized'
        : ocspLeaf === 'stale' || ocspIntermediate === 'stale' ? 'stale'
          : ocspLeaf === 'unknown' || ocspIntermediate === 'unknown' ? 'unknown' : 'missing';
  addStep(
    steps,
    'OCSP revocation check',
    !ocspRevoked && ocspEvidence !== 'unauthorized',
    `Leaf=${ocspLeaf}, intermediate=${ocspIntermediate}. ${ocspEvidence === 'good'
      ? 'Both current responses verified against their direct issuers.'
      : ocspRevoked ? 'A revoked status was reported; reject the chain.'
        : ocspEvidence === 'unauthorized' ? 'A supplied response has an invalid signer; reject it regardless of fail-open policy.'
        : 'No current, authenticated good status for both certificates.'}`,
    ocspEvidence,
  );

  const policyAccepts = policy === 'allow-unknown' || ocspEvidence === 'good';
  addStep(steps, 'Revocation evidence policy', policyAccepts,
    policy === 'allow-unknown'
      ? 'Fail-open policy tolerates missing, unknown, or stale evidence, but never treats it as good; a supplied invalid signature fails separately.'
      : policyAccepts
        ? 'Strict policy has current, issuer-signed good evidence for both non-root certificates.'
        : 'Strict policy requires current, issuer-signed good evidence for both non-root certificates.',
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

/** Policy reachability over issuer links; this does not imply descendant key theft.
 * Subjects are unique identifiers in this teaching graph, not a general PKI path builder.
 */
export function issuerDescendants(certificates: Certificate[], issuer: string | null): Set<string> {
  const reached = new Set<string>();
  const queue = issuer ? [issuer] : [];
  while (queue.length) {
    const subject = queue.shift()!;
    if (reached.has(subject)) continue;
    reached.add(subject);
    for (const cert of certificates) if (cert.issuer === subject && !reached.has(cert.subject)) queue.push(cert.subject);
  }
  return reached;
}

export function compromisedSubtree(
  chain: CertificateChain,
  compromisedCa: CompromisedCa | null,
): Set<string> {
  return issuerDescendants([chain.root.cert, chain.intermediate.cert, chain.leaf.cert],
    compromisedCa ? chain[compromisedCa].cert.subject : null);
}
