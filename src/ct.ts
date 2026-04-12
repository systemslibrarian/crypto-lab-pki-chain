import type { Certificate } from './pki';

export interface CtLeaf {
  certificate: Certificate;
  certHash: string;
  timestamp: number;
}

export interface SignedCertificateTimestamp {
  logId: string;
  timestamp: number;
  entryHash: string;
  signature: ArrayBuffer;
  algorithm: 'ECDSA_P256_SHA256';
}

export interface InclusionProof {
  leafIndex: number;
  treeSize: number;
  leafHash: string;
  auditPath: Array<{ hash: string; position: 'left' | 'right' }>;
  rootHash: string;
}

export interface ConsistencyProof {
  oldSize: number;
  newSize: number;
  oldRoot: string;
  newRoot: string;
  leavesForNewTree: string[];
}

export interface MisissuanceResult {
  suspicious: boolean;
  reason: string;
}

export interface CtLog {
  size: number;
  logId: string;
  leaves: CtLeaf[];
  submitCertificate: (certificate: Certificate) => Promise<SignedCertificateTimestamp>;
  rootHash: () => Promise<string>;
  generateInclusionProof: (leafIndex: number, treeSize?: number) => Promise<InclusionProof>;
  verifyInclusionProof: (proof: InclusionProof) => Promise<boolean>;
  generateConsistencyProof: (oldSize: number, newSize: number) => Promise<ConsistencyProof>;
  verifyConsistencyProof: (proof: ConsistencyProof) => Promise<boolean>;
  detectMisissuance: (
    certificate: Certificate,
    expectedIssuers: Set<string>,
  ) => MisissuanceResult;
}

interface MerkleLevel {
  hashes: string[];
}

interface CtEngineState {
  keyPair: CryptoKeyPair;
  logId: string;
  leaves: CtLeaf[];
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex input.');
  }

  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', data as Uint8Array<ArrayBuffer>);
  return toHex(digest);
}

function certCanonicalBytes(certificate: Certificate): Uint8Array {
  const payload = JSON.stringify({
    subject: certificate.subject,
    issuer: certificate.issuer,
    publicKey: certificate.publicKey,
    validFrom: certificate.validFrom,
    validTo: certificate.validTo,
    serialNumber: certificate.serialNumber,
    signature: toHex(certificate.signature),
  });

  return new TextEncoder().encode(payload);
}

async function hashLeaf(certBytes: Uint8Array): Promise<string> {
  const prefixed = concatBytes(new Uint8Array([0x00]), certBytes);
  return sha256Hex(prefixed);
}

async function hashNode(leftHex: string, rightHex: string): Promise<string> {
  const input = concatBytes(
    new Uint8Array([0x01]),
    hexToBytes(leftHex),
    hexToBytes(rightHex),
  );
  return sha256Hex(input);
}

async function merkleLevels(leafHashes: string[]): Promise<MerkleLevel[]> {
  if (leafHashes.length === 0) {
    return [{ hashes: [] }];
  }

  const levels: MerkleLevel[] = [{ hashes: leafHashes.slice() }];
  while (levels[levels.length - 1].hashes.length > 1) {
    const current = levels[levels.length - 1].hashes;
    const next: string[] = [];

    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = current[i + 1] ?? current[i];
      next.push(await hashNode(left, right));
    }

    levels.push({ hashes: next });
  }

  return levels;
}

async function rootFromLeaves(leafHashes: string[]): Promise<string> {
  if (leafHashes.length === 0) {
    return sha256Hex(new Uint8Array([0xff]));
  }
  const levels = await merkleLevels(leafHashes);
  return levels[levels.length - 1].hashes[0];
}

async function createSct(
  state: CtEngineState,
  entryHash: string,
  timestamp: number,
): Promise<SignedCertificateTimestamp> {
  const payload = new TextEncoder().encode(`${timestamp}:${entryHash}`);
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    state.keyPair.privateKey,
    payload,
  );

  return {
    logId: state.logId,
    timestamp,
    entryHash,
    signature,
    algorithm: 'ECDSA_P256_SHA256',
  };
}

async function verifySctSignature(
  publicKey: CryptoKey,
  sct: SignedCertificateTimestamp,
): Promise<boolean> {
  const payload = new TextEncoder().encode(`${sct.timestamp}:${sct.entryHash}`);
  return crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: 'SHA-256',
    },
    publicKey,
    sct.signature,
    payload,
  );
}

export async function createCtLog(): Promise<CtLog> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign', 'verify'],
  );

  const spki = await crypto.subtle.exportKey('spki', keyPair.publicKey);
  const logId = await sha256Hex(new Uint8Array(spki));

  const state: CtEngineState = {
    keyPair,
    logId,
    leaves: [],
  };

  return {
    get size() {
      return state.leaves.length;
    },
    get logId() {
      return state.logId;
    },
    get leaves() {
      return state.leaves;
    },
    async submitCertificate(certificate: Certificate): Promise<SignedCertificateTimestamp> {
      const timestamp = Date.now();
      const certBytes = certCanonicalBytes(certificate);
      const certHash = await hashLeaf(certBytes);

      state.leaves.push({
        certificate,
        certHash,
        timestamp,
      });

      return createSct(state, certHash, timestamp);
    },
    async rootHash(): Promise<string> {
      return rootFromLeaves(state.leaves.map((leaf) => leaf.certHash));
    },
    async generateInclusionProof(leafIndex: number, treeSize = state.leaves.length): Promise<InclusionProof> {
      if (treeSize < 1 || treeSize > state.leaves.length) {
        throw new Error('Tree size out of range.');
      }
      if (leafIndex < 0 || leafIndex >= treeSize) {
        throw new Error('Leaf index out of range for requested tree size.');
      }

      const hashes = state.leaves.slice(0, treeSize).map((leaf) => leaf.certHash);
      const levels = await merkleLevels(hashes);
      const auditPath: InclusionProof['auditPath'] = [];

      let position = leafIndex;
      for (let level = 0; level < levels.length - 1; level += 1) {
        const nodes = levels[level].hashes;
        const isLeft = position % 2 === 0;
        const siblingIndex = isLeft ? position + 1 : position - 1;
        const siblingHash = nodes[siblingIndex] ?? nodes[position];
        auditPath.push({
          hash: siblingHash,
          position: isLeft ? 'right' : 'left',
        });
        position = Math.floor(position / 2);
      }

      const leafHash = hashes[leafIndex];
      const rootHash = levels[levels.length - 1].hashes[0];

      return {
        leafIndex,
        treeSize,
        leafHash,
        auditPath,
        rootHash,
      };
    },
    async verifyInclusionProof(proof: InclusionProof): Promise<boolean> {
      let current = proof.leafHash;
      for (const sibling of proof.auditPath) {
        if (sibling.position === 'left') {
          current = await hashNode(sibling.hash, current);
        } else {
          current = await hashNode(current, sibling.hash);
        }
      }
      return current === proof.rootHash;
    },
    async generateConsistencyProof(oldSize: number, newSize: number): Promise<ConsistencyProof> {
      if (oldSize < 1 || newSize < 1) {
        throw new Error('Tree sizes must be at least 1.');
      }
      if (oldSize > newSize) {
        throw new Error('Old tree size must be <= new tree size.');
      }
      if (newSize > state.leaves.length) {
        throw new Error('Requested size exceeds current log size.');
      }

      const allLeafHashes = state.leaves.slice(0, newSize).map((leaf) => leaf.certHash);
      const oldRoot = await rootFromLeaves(allLeafHashes.slice(0, oldSize));
      const newRoot = await rootFromLeaves(allLeafHashes);

      return {
        oldSize,
        newSize,
        oldRoot,
        newRoot,
        leavesForNewTree: allLeafHashes,
      };
    },
    async verifyConsistencyProof(proof: ConsistencyProof): Promise<boolean> {
      if (proof.oldSize > proof.newSize) {
        return false;
      }
      if (proof.leavesForNewTree.length !== proof.newSize) {
        return false;
      }

      const computedOld = await rootFromLeaves(proof.leavesForNewTree.slice(0, proof.oldSize));
      const computedNew = await rootFromLeaves(proof.leavesForNewTree);
      return computedOld === proof.oldRoot && computedNew === proof.newRoot;
    },
    detectMisissuance(certificate: Certificate, expectedIssuers: Set<string>): MisissuanceResult {
      if (expectedIssuers.size === 0) {
        return {
          suspicious: false,
          reason: 'No issuer policy provided for this subject.',
        };
      }

      const validIssuer = expectedIssuers.has(certificate.issuer);
      if (validIssuer) {
        return {
          suspicious: false,
          reason: 'Issuer matches expected issuance policy.',
        };
      }

      return {
        suspicious: true,
        reason: `Issuer ${certificate.issuer} is outside expected policy for ${certificate.subject}.`,
      };
    },
  };
}

export async function verifySct(
  logPublicKey: CryptoKey,
  sct: SignedCertificateTimestamp,
): Promise<boolean> {
  return verifySctSignature(logPublicKey, sct);
}
