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
  /** RFC 6962 consistency proof path — an O(log n) set of subtree hashes, NOT the full leaf set. */
  proof: string[];
}

export interface MisissuanceResult {
  suspicious: boolean;
  reason: string;
}

/**
 * A drawable node of the RFC 6962 Merkle tree. `level` 0 is the leaf row;
 * `span` is the inclusive `[start, end]` leaf index range the node covers, so a
 * renderer can lay nodes out horizontally over their leaves. `hash` is the real
 * SHA-256 Merkle hash for that subtree — never a placeholder.
 */
export interface MerkleTreeNode {
  hash: string;
  level: number;
  /** Inclusive leaf-index range this subtree covers. */
  span: [number, number];
  isLeaf: boolean;
  children: MerkleTreeNode[];
}

/** A key that uniquely identifies a tree node by its leaf-index span. */
export function nodeKey(node: { span: [number, number] }): string {
  return `${node.span[0]}-${node.span[1]}`;
}

export interface CtLog {
  size: number;
  logId: string;
  leaves: CtLeaf[];
  submitCertificate: (certificate: Certificate) => Promise<SignedCertificateTimestamp>;
  rootHash: (treeSize?: number) => Promise<string>;
  generateInclusionProof: (leafIndex: number, treeSize?: number) => Promise<InclusionProof>;
  verifyInclusionProof: (proof: InclusionProof) => Promise<boolean>;
  /** Full drawable RFC 6962 tree with real per-node Merkle hashes. */
  treeLayout: (treeSize?: number) => Promise<MerkleTreeNode>;
  generateConsistencyProof: (oldSize: number, newSize: number) => Promise<ConsistencyProof>;
  verifyConsistencyProof: (proof: ConsistencyProof) => Promise<boolean>;
  detectMisissuance: (
    certificate: Certificate,
    expectedIssuers: Set<string>,
  ) => MisissuanceResult;
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

// ── RFC 6962 Merkle tree hashing ──────────────────────────────────────────
// The structure below follows RFC 6962 §2.1 exactly: leaves are prefixed with
// 0x00, interior nodes with 0x01, and a tree of n leaves is split at the
// LARGEST power of two strictly less than n. Crucially, lone right-hand nodes
// are NOT duplicated (the historical Bitcoin-style flaw) — that is what lets
// CT produce compact O(log n) inclusion and consistency proofs.

/** Leaf hash: H(0x00 || cert bytes). */
async function hashLeaf(certBytes: Uint8Array): Promise<string> {
  return sha256Hex(concatBytes(new Uint8Array([0x00]), certBytes));
}

/** Interior node hash: H(0x01 || left || right). */
async function hashNode(leftHex: string, rightHex: string): Promise<string> {
  return sha256Hex(concatBytes(new Uint8Array([0x01]), hexToBytes(leftHex), hexToBytes(rightHex)));
}

/** Largest power of two strictly less than n (n >= 2). */
function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) {
    k *= 2;
  }
  return k;
}

/** Merkle Tree Hash (MTH) over a list of already-computed leaf hashes. */
async function merkleTreeHash(leafHashes: string[]): Promise<string> {
  if (leafHashes.length === 0) {
    // MTH({}) = SHA-256() of the empty string (RFC 6962 §2.1).
    return sha256Hex(new Uint8Array(0));
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }
  const k = largestPowerOfTwoBelow(leafHashes.length);
  const left = await merkleTreeHash(leafHashes.slice(0, k));
  const right = await merkleTreeHash(leafHashes.slice(k));
  return hashNode(left, right);
}

type AuditStep = { hash: string; position: 'left' | 'right' };

/** RFC 6962 PATH(m, D[n]) — the audit path for leaf m, returned leaf→root. */
async function auditPath(m: number, leafHashes: string[]): Promise<AuditStep[]> {
  const n = leafHashes.length;
  if (n <= 1) {
    return [];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m < k) {
    const sub = await auditPath(m, leafHashes.slice(0, k));
    const sibling = await merkleTreeHash(leafHashes.slice(k));
    return [...sub, { hash: sibling, position: 'right' }];
  }
  const sub = await auditPath(m - k, leafHashes.slice(k));
  const sibling = await merkleTreeHash(leafHashes.slice(0, k));
  return [...sub, { hash: sibling, position: 'left' }];
}

/** RFC 6962 SUBPROOF(m, D[n], b) — the building block for consistency proofs. */
async function subProof(m: number, leafHashes: string[], b: boolean): Promise<string[]> {
  const n = leafHashes.length;
  if (m === n) {
    return b ? [] : [await merkleTreeHash(leafHashes)];
  }
  const k = largestPowerOfTwoBelow(n);
  if (m <= k) {
    const sub = await subProof(m, leafHashes.slice(0, k), b);
    return [...sub, await merkleTreeHash(leafHashes.slice(k))];
  }
  const sub = await subProof(m - k, leafHashes.slice(k), false);
  return [...sub, await merkleTreeHash(leafHashes.slice(0, k))];
}

/** RFC 6962 PROOF(m, D[n]) — consistency proof between sizes m and n. */
async function consistencyPath(m: number, leafHashes: string[]): Promise<string[]> {
  if (m === 0 || m === leafHashes.length) {
    return [];
  }
  return subProof(m, leafHashes, true);
}

/**
 * Canonical RFC 6962 §2.1.2 consistency-proof verification. Reconstructs BOTH
 * the old and new roots from the compact proof path and checks they match.
 */
async function verifyConsistency(
  oldSize: number,
  newSize: number,
  oldRoot: string,
  newRoot: string,
  path: string[],
): Promise<boolean> {
  if (oldSize < 0 || oldSize > newSize) {
    return false;
  }
  if (oldSize === newSize) {
    return path.length === 0 && oldRoot === newRoot;
  }
  if (oldSize === 0) {
    // The empty tree is consistent with any later tree; the proof carries no nodes.
    return path.length === 0;
  }

  let node = oldSize - 1;
  let lastNode = newSize - 1;
  while (node % 2 === 1) {
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }

  let index = 0;
  const next = (): string | undefined => path[index++];

  let oldHash: string;
  let newHash: string;
  if (node > 0) {
    const seed = next();
    if (seed === undefined) {
      return false;
    }
    oldHash = seed;
    newHash = seed;
  } else {
    oldHash = oldRoot;
    newHash = oldRoot;
  }

  while (node > 0) {
    if (node % 2 === 1) {
      const sibling = next();
      if (sibling === undefined) {
        return false;
      }
      oldHash = await hashNode(sibling, oldHash);
      newHash = await hashNode(sibling, newHash);
    } else if (node < lastNode) {
      const sibling = next();
      if (sibling === undefined) {
        return false;
      }
      newHash = await hashNode(newHash, sibling);
    }
    node = Math.floor(node / 2);
    lastNode = Math.floor(lastNode / 2);
  }

  while (lastNode > 0) {
    const sibling = next();
    if (sibling === undefined) {
      return false;
    }
    newHash = await hashNode(newHash, sibling);
    lastNode = Math.floor(lastNode / 2);
  }

  return oldHash === oldRoot && newHash === newRoot && index === path.length;
}

/**
 * Build the drawable RFC 6962 tree from leaf hashes, recording each subtree's
 * inclusive leaf-index span. Splits at the largest power of two below n and does
 * NOT duplicate lone right nodes — identical to `merkleTreeHash`, so the node
 * hashes shown to the learner are the exact ones the proofs recompute.
 */
async function buildTree(leafHashes: string[], offset = 0): Promise<MerkleTreeNode> {
  const n = leafHashes.length;
  if (n === 1) {
    return {
      hash: leafHashes[0],
      level: 0,
      span: [offset, offset],
      isLeaf: true,
      children: [],
    };
  }
  const k = largestPowerOfTwoBelow(n);
  const left = await buildTree(leafHashes.slice(0, k), offset);
  const right = await buildTree(leafHashes.slice(k), offset + k);
  return {
    hash: await hashNode(left.hash, right.hash),
    level: Math.max(left.level, right.level) + 1,
    span: [offset, offset + n - 1],
    isLeaf: false,
    children: [left, right],
  };
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

  const leafHashesUpTo = (treeSize: number): string[] =>
    state.leaves.slice(0, treeSize).map((leaf) => leaf.certHash);

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
    async rootHash(treeSize = state.leaves.length): Promise<string> {
      if (treeSize < 0 || treeSize > state.leaves.length) {
        throw new Error('Tree size out of range.');
      }
      return merkleTreeHash(leafHashesUpTo(treeSize));
    },
    async generateInclusionProof(leafIndex: number, treeSize = state.leaves.length): Promise<InclusionProof> {
      if (treeSize < 1 || treeSize > state.leaves.length) {
        throw new Error('Tree size out of range.');
      }
      if (leafIndex < 0 || leafIndex >= treeSize) {
        throw new Error('Leaf index out of range for requested tree size.');
      }

      const hashes = leafHashesUpTo(treeSize);
      const path = await auditPath(leafIndex, hashes);
      const rootHash = await merkleTreeHash(hashes);

      return {
        leafIndex,
        treeSize,
        leafHash: hashes[leafIndex],
        auditPath: path,
        rootHash,
      };
    },
    async treeLayout(treeSize = state.leaves.length): Promise<MerkleTreeNode> {
      if (treeSize < 1 || treeSize > state.leaves.length) {
        throw new Error('Tree size out of range.');
      }
      return buildTree(leafHashesUpTo(treeSize));
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

      const newHashes = leafHashesUpTo(newSize);
      const oldRoot = await merkleTreeHash(newHashes.slice(0, oldSize));
      const newRoot = await merkleTreeHash(newHashes);
      const proof = await consistencyPath(oldSize, newHashes);

      return {
        oldSize,
        newSize,
        oldRoot,
        newRoot,
        proof,
      };
    },
    async verifyConsistencyProof(proof: ConsistencyProof): Promise<boolean> {
      return verifyConsistency(proof.oldSize, proof.newSize, proof.oldRoot, proof.newRoot, proof.proof);
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
