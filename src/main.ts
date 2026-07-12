import './style.css';
import {
  createCtLog,
  type CtLog,
  type InclusionProof,
  type SignedCertificateTimestamp,
  type ConsistencyProof,
  type MisissuanceResult,
} from './ct';
import {
  createDemoChain,
  createTrustStore,
  trustAnchorFingerprint,
  validateChain,
  createCrl,
  createOcspResponder,
  compromisedSubtree,
  type Certificate,
  type CertificateChain,
  type SignedCertificate,
  type ValidationResult,
  type TrustStore,
  type CompromisedCa,
} from './pki';

type CertNode = 'root' | 'intermediate' | 'leaf';
type Theme = 'dark' | 'light';
type TrustContext = 'browser' | 'os' | 'application';
type PqMode = 'classical' | 'mldsa' | 'hybrid';

interface AppState {
  chain: CertificateChain;
  selectedNode: CertNode;
  validation: ValidationResult | null;
  trustStores: Record<TrustContext, TrustStore>;
  trustContext: TrustContext;
  tamperedNodes: Set<CertNode>;
  revokeViaCrl: boolean;
  revokeViaOcsp: boolean;
  compromisedCa: CompromisedCa | null;
  ctLog: CtLog;
  latestSct: SignedCertificateTimestamp | null;
  latestProof: InclusionProof | null;
  latestProofValid: boolean | null;
  latestConsistency: ConsistencyProof | null;
  latestConsistencyValid: boolean | null;
  misissuance: MisissuanceResult | null;
  theme: Theme;
  pqMode: PqMode;
  rootFingerprint: string;
}

const app = document.querySelector<HTMLDivElement>('#app');
if (!app) {
  throw new Error('Missing app root element.');
}

const TAMPER_MARK = ' [tampered]';

function shortHex(value: string, count = 12): string {
  return value.length > count * 2 ? `${value.slice(0, count)}...${value.slice(-count)}` : value;
}

function shortSubject(value: string): string {
  return value.replace('CN=', '');
}

/** Apply a tamper to a certificate — flip a single signed field after issuance. */
function applyTamper(cert: Certificate): Certificate {
  return {
    ...cert,
    subject: `${cert.subject}${TAMPER_MARK}`,
  };
}

function tamperedSigned(signed: SignedCertificate, on: boolean): SignedCertificate {
  return on ? { ...signed, cert: applyTamper(signed.cert) } : signed;
}

/**
 * The chain as the validator sees it: pristine certificates with any toggled
 * tamper re-applied on top. The original `state.chain` is never mutated, so
 * tampering is fully reversible and learners can flip PASS↔FAIL at will.
 */
function effectiveChain(state: AppState): CertificateChain {
  return {
    root: tamperedSigned(state.chain.root, state.tamperedNodes.has('root')),
    intermediate: tamperedSigned(state.chain.intermediate, state.tamperedNodes.has('intermediate')),
    leaf: tamperedSigned(state.chain.leaf, state.tamperedNodes.has('leaf')),
  };
}

function certAt(state: AppState, node: CertNode): Certificate {
  const chain = effectiveChain(state);
  if (node === 'root') {
    return chain.root.cert;
  }
  if (node === 'intermediate') {
    return chain.intermediate.cert;
  }
  return chain.leaf.cert;
}

async function recomputeValidation(state: AppState): Promise<void> {
  const chain = effectiveChain(state);

  const crls = state.revokeViaCrl
    ? [createCrl(chain.leaf.cert.issuer, [chain.leaf.cert.serialNumber])]
    : [];

  const ocsp = state.revokeViaOcsp
    ? [
        createOcspResponder(chain.leaf.cert.issuer, [
          { serialNumber: chain.leaf.cert.serialNumber, status: 'revoked' },
        ]),
      ]
    : [];

  state.validation = await validateChain(
    chain,
    state.trustStores[state.trustContext],
    crls,
    ocsp,
  );
}

interface PqProfile {
  mode: PqMode;
  label: string;
  alg: string;
  sigBytes: number;
  keyBytes: number;
  measured: boolean;
  note: string;
}

function pqProfiles(state: AppState): PqProfile[] {
  // Real, measured classical footprint from the live chain's leaf certificate.
  const classicalSig = state.chain.leaf.cert.signature.byteLength;
  const classicalKey = 65; // Uncompressed P-256 public point: 1 + 32 + 32 bytes.

  // Post-quantum sizes are NIST FIPS 204 ML-DSA-44 reference values. WebCrypto
  // cannot yet produce ML-DSA signatures, so these are stated, not generated.
  const mldsaSig = 2420;
  const mldsaKey = 1312;

  return [
    {
      mode: 'classical',
      label: 'ECDSA P-256',
      alg: 'ECDSA P-256 / SHA-256',
      sigBytes: classicalSig,
      keyBytes: classicalKey,
      measured: true,
      note: 'Today’s WebPKI baseline. Tiny artifacts, universal browser and HSM support — but Shor’s algorithm breaks it once a cryptographically relevant quantum computer exists.',
    },
    {
      mode: 'mldsa',
      label: 'ML-DSA-44',
      alg: 'ML-DSA-44 (FIPS 204, Dilithium family)',
      sigBytes: mldsaSig,
      keyBytes: mldsaKey,
      measured: false,
      note: 'Quantum-resistant lattice signatures. ~38× larger signatures inflate every handshake and certificate — the cost of post-quantum security.',
    },
    {
      mode: 'hybrid',
      label: 'P-256 + ML-DSA-44',
      alg: 'Hybrid dual signature (classical + PQ)',
      sigBytes: classicalSig + mldsaSig,
      keyBytes: classicalKey + mldsaKey,
      measured: false,
      note: 'The expected migration path: a relying party that trusts either algorithm stays secure. Carries both signatures, so it is the largest — but it is safe even if one scheme is later broken.',
    },
  ];
}

function pqBarsMarkup(state: AppState): string {
  const profiles = pqProfiles(state);
  const maxSig = Math.max(...profiles.map((p) => p.sigBytes));

  return profiles
    .map((p) => {
      const width = Math.max(2, Math.round((p.sigBytes / maxSig) * 100));
      const active = state.pqMode === p.mode;
      return `
        <div class="pq-bar-row ${active ? 'active' : ''}">
          <span class="pq-bar-label">${p.label}${p.measured ? ' <span class="pq-tag">measured</span>' : ''}</span>
          <span class="pq-bar-track"><span class="pq-bar-fill" style="width: ${width}%"></span></span>
          <span class="pq-bar-value mono">${p.sigBytes.toLocaleString()} B</span>
        </div>`;
    })
    .join('');
}

function exhibitsMarkup(state: AppState): string {
  const selected = certAt(state, state.selectedNode);
  const compromiseSet = compromisedSubtree(state.chain, state.compromisedCa);
  const chainTrusted = state.validation?.ok ?? false;
  const signatureBytes = selected.signature.byteLength;
  const tamperCount = state.tamperedNodes.size;
  const activePq = pqProfiles(state).find((p) => p.mode === state.pqMode)!;

  const tamperLabel = (node: CertNode, name: string): string =>
    state.tamperedNodes.has(node) ? `Repair ${name}` : `Tamper ${name}`;

  return `
    <header class="cl-hero panel">
      <div class="hero-actions">
        <button id="reset-lab" class="btn ghost" type="button" aria-label="Reset all lab scenarios to defaults"${tamperCount === 0 && !state.revokeViaCrl && !state.revokeViaOcsp && !state.compromisedCa && state.trustContext === 'browser' ? ' disabled' : ''}>Reset lab</button>
        <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to ${state.theme === 'dark' ? 'light' : 'dark'} mode">
          <span aria-hidden="true">${state.theme === 'dark' ? '🌙' : '☀️'}</span>
        </button>
      </div>
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">PKI Chain</h1>
        <p class="cl-hero-sub">Certificate Chain Trust &middot; X.509 &middot; RFC 5280 &middot; CT (RFC 6962)</p>
        <p class="cl-hero-desc">Walk a Root &rarr; Intermediate &rarr; Leaf chain link-by-link, tampering, revoking, and compromising CAs while live <code>crypto.subtle</code> signatures, Merkle inclusion/consistency proofs, and PQ signature sizes recompute in the browser.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">Every HTTPS connection rests on this chain. One stolen CA key or an unlisted root can silently forge trusted certificates for any site &mdash; so knowing how validation, revocation, and Certificate Transparency actually contain that blast radius is core web security.</p>
      </aside>
    </header>

    <section class="panel exhibit" id="exhibit-1" aria-labelledby="ex1-heading">
      <h2 id="ex1-heading">Exhibit 1 &mdash; The Chain</h2>
      <p class="caption">Root CA &rarr; Intermediate CA &rarr; Leaf certificate with trust propagation from anchor to endpoint.</p>
      <div class="chain-row ${chainTrusted ? 'trust-flow-on' : ''}" role="group" aria-label="Certificate chain">
        <button type="button" class="cert-chip ${state.selectedNode === 'root' ? 'active' : ''} ${compromiseSet.has(state.chain.root.cert.subject) ? 'compromised' : ''}" data-select="root" aria-pressed="${state.selectedNode === 'root'}" aria-label="Root CA certificate${compromiseSet.has(state.chain.root.cert.subject) ? ', compromised' : ''}">Root CA</button>
        <span class="arrow" aria-hidden="true">&rarr;</span>
        <button type="button" class="cert-chip ${state.selectedNode === 'intermediate' ? 'active' : ''} ${compromiseSet.has(state.chain.intermediate.cert.subject) ? 'compromised' : ''}" data-select="intermediate" aria-pressed="${state.selectedNode === 'intermediate'}" aria-label="Intermediate CA certificate${compromiseSet.has(state.chain.intermediate.cert.subject) ? ', compromised' : ''}">Intermediate</button>
        <span class="arrow" aria-hidden="true">&rarr;</span>
        <button type="button" class="cert-chip ${state.selectedNode === 'leaf' ? 'active' : ''} ${compromiseSet.has(state.chain.leaf.cert.subject) ? 'compromised' : ''}" data-select="leaf" aria-pressed="${state.selectedNode === 'leaf'}" aria-label="Leaf certificate${compromiseSet.has(state.chain.leaf.cert.subject) ? ', compromised' : ''}">Leaf</button>
      </div>
      <div class="cert-inspector" role="region" aria-label="Certificate details for ${state.selectedNode}" aria-live="polite">
        <dl class="cert-fields">
          <dt>Subject</dt><dd>${selected.subject}</dd>
          <dt>Issuer</dt><dd>${selected.issuer}</dd>
          <dt>Serial</dt><dd><span class="mono">${selected.serialNumber}</span></dd>
          <dt>Validity</dt><dd>${new Date(selected.validFrom).toLocaleDateString()} &ndash; ${new Date(selected.validTo).toLocaleDateString()}</dd>
          <dt>Public Key</dt><dd>${selected.publicKey.kty ?? 'unknown'} / ${(selected.publicKey.crv ?? selected.publicKey.alg ?? 'n/a')}</dd>
          <dt>Signature Size</dt><dd>${signatureBytes} bytes</dd>
        </dl>
      </div>
      <p class="teach"><strong>How trust flows:</strong> each certificate carries the <em>subject</em>&rsquo;s public key, signed by its <em>issuer</em>&rsquo;s private key. The Root signs itself; it signs the Intermediate; the Intermediate signs the Leaf. Trust an anchor and you transitively trust everything it vouches for &mdash; until one signature fails to verify.</p>
    </section>

    <section class="panel exhibit" id="exhibit-2" aria-labelledby="ex2-heading">
      <h2 id="ex2-heading">Exhibit 2 &mdash; Chain Validation</h2>
      <p class="caption">Real WebCrypto signature verification at every link, plus trust anchor and revocation checks.</p>
      <div class="control-row" role="toolbar" aria-label="Validation controls">
        <button id="run-validation" class="btn" type="button">Run Validation</button>
        <button class="btn ghost ${state.tamperedNodes.has('root') ? 'tampered' : ''}" data-tamper="root" type="button" aria-pressed="${state.tamperedNodes.has('root')}">${tamperLabel('root', 'Root')}</button>
        <button class="btn ghost ${state.tamperedNodes.has('intermediate') ? 'tampered' : ''}" data-tamper="intermediate" type="button" aria-pressed="${state.tamperedNodes.has('intermediate')}">${tamperLabel('intermediate', 'Intermediate')}</button>
        <button class="btn ghost ${state.tamperedNodes.has('leaf') ? 'tampered' : ''}" data-tamper="leaf" type="button" aria-pressed="${state.tamperedNodes.has('leaf')}">${tamperLabel('leaf', 'Leaf')}</button>
      </div>
      <fieldset class="control-row revocation-fieldset">
        <legend class="sr-only">Revocation simulation</legend>
        <label><input id="toggle-crl" type="checkbox" ${state.revokeViaCrl ? 'checked' : ''} /> Simulate CRL revocation</label>
        <label><input id="toggle-ocsp" type="checkbox" ${state.revokeViaOcsp ? 'checked' : ''} /> Simulate OCSP revoked</label>
      </fieldset>
      <ul class="step-list" aria-label="Validation steps" role="list">
        ${(state.validation?.steps ?? [])
          .map(
            (step) => `<li class="${step.ok ? 'pass' : 'fail'}" aria-label="${step.label}: ${step.ok ? 'passed' : 'failed'}"><strong>${step.label}:</strong> ${step.details}</li>`,
          )
          .join('')}
      </ul>
      <p class="status ${state.validation?.ok ? 'pass' : 'fail'}" role="status" aria-live="polite">Overall: ${state.validation?.ok ? 'PASS' : 'FAIL'}</p>
      <p class="teach"><strong>Try it:</strong> a signature covers the exact bytes of the fields it signs. <em>Tamper</em> any certificate &mdash; this flips one signed field <em>after</em> issuance &mdash; and that link&rsquo;s signature check fails immediately, because the issuer never signed the altered bytes. Click again to <em>repair</em> and watch it pass. This is why an attacker cannot edit a certificate without the issuer&rsquo;s private key.</p>
    </section>

    <section class="panel exhibit" id="exhibit-3" aria-labelledby="ex3-heading">
      <h2 id="ex3-heading">Exhibit 3 &mdash; Trust Stores</h2>
      <p class="caption">The same chain can be accepted or rejected depending on browser, OS, or app trust roots.</p>
      <div class="tab-row" role="tablist" aria-label="Trust store context">
        <button class="tab ${state.trustContext === 'browser' ? 'active' : ''}" data-context="browser" type="button" role="tab" aria-selected="${state.trustContext === 'browser'}">Browser Store</button>
        <button class="tab ${state.trustContext === 'os' ? 'active' : ''}" data-context="os" type="button" role="tab" aria-selected="${state.trustContext === 'os'}">OS Store</button>
        <button class="tab ${state.trustContext === 'application' ? 'active' : ''}" data-context="application" type="button" role="tab" aria-selected="${state.trustContext === 'application'}">Application Store</button>
      </div>
      <p>Current context: <strong>${state.trustContext}</strong></p>
      <p>Root fingerprint: <span class="mono">${shortHex(state.rootFingerprint, 18)}</span></p>
      <p>Context trust decision: <strong class="${state.validation?.ok ? 'pass' : 'fail'}">${state.validation?.ok ? 'Trusted' : 'Rejected'}</strong></p>
      <p class="teach"><strong>Why the OS store rejects this chain:</strong> the same cryptographically valid chain is <em>Trusted</em> by the Browser and Application stores but <em>Rejected</em> by the OS store &mdash; not because any signature is wrong, but because that store does not list this Root&rsquo;s fingerprint as an anchor. Trust is a policy decision about <em>which roots you choose to believe</em>, not a property of the math.</p>
      <div class="incident-grid">
        <article><h3>DigiNotar (2011)</h3><p>Fraudulent certs for major domains triggered emergency root distrust.</p></article>
        <article><h3>Symantec Distrust (2017)</h3><p>Chrome removed trust after systemic issuance and audit failures.</p></article>
        <article><h3>TrustCor Removal (2022)</h3><p>Mozilla removed root trust over ownership and compliance concerns.</p></article>
      </div>
    </section>

    <section class="panel exhibit" id="exhibit-4" aria-labelledby="ex4-heading">
      <h2 id="ex4-heading">Exhibit 4 &mdash; CA Compromise</h2>
      <p class="caption">Mark a CA as compromised and observe cascading distrust across its issued subtree.</p>
      <div class="tab-row" role="tablist" aria-label="Compromise scenario">
        <button class="tab ${state.compromisedCa === null ? 'active' : ''}" data-compromise="none" type="button" role="tab" aria-selected="${state.compromisedCa === null}">No Compromise</button>
        <button class="tab ${state.compromisedCa === 'intermediate' ? 'active' : ''}" data-compromise="intermediate" type="button" role="tab" aria-selected="${state.compromisedCa === 'intermediate'}">Intermediate Compromised</button>
        <button class="tab ${state.compromisedCa === 'root' ? 'active' : ''}" data-compromise="root" type="button" role="tab" aria-selected="${state.compromisedCa === 'root'}">Root Compromised</button>
      </div>
      <p>Untrusted subtree:</p>
      <ul class="subtree-list" aria-live="polite">
        <li class="${compromiseSet.has(state.chain.root.cert.subject) ? 'fail' : 'pass'}">${shortSubject(state.chain.root.cert.subject)}</li>
        <li class="${compromiseSet.has(state.chain.intermediate.cert.subject) ? 'fail' : 'pass'}">${shortSubject(state.chain.intermediate.cert.subject)}</li>
        <li class="${compromiseSet.has(state.chain.leaf.cert.subject) ? 'fail' : 'pass'}">${shortSubject(state.chain.leaf.cert.subject)}</li>
      </ul>
      <p class="teach"><strong>Blast radius:</strong> a stolen CA private key can mint <em>new</em> valid certificates for any name, so every certificate beneath the compromised CA must be treated as untrustworthy &mdash; even leaves that were issued correctly. Compromise the Intermediate and the Leaf falls; compromise the Root and the entire hierarchy falls. This is why Root keys live offline in HSMs and day-to-day issuance is delegated to Intermediates.</p>
      <p class="incident-note"><strong>DigiNotar 2011:</strong> attacker-issued fraudulent certificates (including google.com), prompting browser vendors to distrust the CA and break trust for all descendants.</p>
    </section>

    <section class="panel exhibit" id="exhibit-5" aria-labelledby="ex5-heading">
      <h2 id="ex5-heading">Exhibit 5 &mdash; Certificate Transparency</h2>
      <p class="caption">Submit certificates to a simulated append-only log, mint SCTs, verify inclusion, and catch misissuance.</p>
      <div class="control-row">
        <button id="ct-submit" class="btn" type="button">Submit Leaf to CT Log</button>
        <button id="ct-proof" class="btn ghost" type="button" ${state.ctLog.size < 1 ? 'disabled' : ''}>Inclusion Proof</button>
        <button id="ct-consistency" class="btn ghost" type="button" ${state.ctLog.size < 2 ? 'disabled' : ''}>Consistency Proof</button>
        <button id="ct-misissue" class="btn danger" type="button">Simulate Misissuance</button>
      </div>
      <p>Log size: <strong>${state.ctLog.size}</strong> | Log ID: <span class="mono">${shortHex(state.ctLog.logId, 14)}</span></p>
      <p>SCT: ${state.latestSct ? `<span class="mono">${shortHex(state.latestSct.entryHash, 14)}</span> at ${new Date(state.latestSct.timestamp).toLocaleTimeString()}` : 'No SCT generated yet.'}</p>
      <p>Inclusion proof: ${state.latestProof ? `${state.latestProof.auditPath.length} sibling hash${state.latestProof.auditPath.length === 1 ? '' : 'es'} to recompute root, verify=<strong class="${state.latestProofValid ? 'pass' : 'fail'}">${state.latestProofValid ? 'true' : 'false'}</strong>` : 'Not generated.'}</p>
      <p>Consistency proof: ${state.latestConsistency ? `old=${state.latestConsistency.oldSize} &rarr; new=${state.latestConsistency.newSize}, path=${state.latestConsistency.proof.length} hash${state.latestConsistency.proof.length === 1 ? '' : 'es'}, verify=<strong class="${state.latestConsistencyValid ? 'pass' : 'fail'}">${state.latestConsistencyValid ? 'true' : 'false'}</strong>` : 'Not generated.'}</p>
      <p class="status ${state.misissuance?.suspicious ? 'fail' : 'pass'}" role="status" aria-live="polite">Misissuance monitor: ${state.misissuance ? state.misissuance.reason : 'No suspicious issuance observed.'}</p>
      <p class="teach"><strong>What the proofs guarantee (RFC 6962):</strong> the <em>inclusion proof</em> shows your certificate is in the log using only ~log&#8322;(n) sibling hashes &mdash; not the whole log. The <em>consistency proof</em> shows the new tree only <em>appended</em> to the old one and rewrote no history, again with a handful of hashes. Together they make a misbehaving log detectable: it cannot hide a certificate or fork its view without producing a proof that fails to verify.</p>
    </section>

    <section class="panel exhibit" id="exhibit-6" aria-labelledby="ex6-heading">
      <h2 id="ex6-heading">Exhibit 6 &mdash; PQ Migration</h2>
      <p class="caption">Compare classical and post-quantum certificate signature footprints and migration strategy.</p>
      <div class="tab-row" role="tablist" aria-label="Post-quantum algorithm selection">
        <button class="tab ${state.pqMode === 'classical' ? 'active' : ''}" data-pq="classical" type="button" role="tab" aria-selected="${state.pqMode === 'classical'}">P-256</button>
        <button class="tab ${state.pqMode === 'mldsa' ? 'active' : ''}" data-pq="mldsa" type="button" role="tab" aria-selected="${state.pqMode === 'mldsa'}">ML-DSA</button>
        <button class="tab ${state.pqMode === 'hybrid' ? 'active' : ''}" data-pq="hybrid" type="button" role="tab" aria-selected="${state.pqMode === 'hybrid'}">Hybrid</button>
      </div>
      <p class="caption">Signature size (bytes), drawn to scale &mdash; the classical bar is measured from this lab&rsquo;s live chain:</p>
      <div class="pq-bars" aria-label="Signature size comparison">
        ${pqBarsMarkup(state)}
      </div>
      <h3>${activePq.label}</h3>
      <p><strong>Algorithm:</strong> ${activePq.alg}</p>
      <p><strong>Signature footprint:</strong> ${activePq.sigBytes.toLocaleString()} bytes${activePq.measured ? ' (measured live)' : ' (FIPS 204 reference)'}</p>
      <p><strong>Public key footprint:</strong> ${activePq.keyBytes.toLocaleString()} bytes</p>
      <p>${activePq.note}</p>
      <p class="incident-note">Compatibility note: browsers currently validate classical WebPKI signatures; PQ rollouts are expected to use hybrid certificates first. ML-DSA sizes are FIPS 204 reference values — WebCrypto cannot yet generate them.</p>
    </section>

    <footer class="panel footer-note" role="contentinfo">
      <p>Related demos:
        <a href="https://systemslibrarian.github.io/crypto-lab-merkle-vault/">crypto-lab-merkle-vault</a> &middot;
        <a href="https://systemslibrarian.github.io/crypto-lab-web-of-trust/">crypto-lab-web-of-trust</a> &middot;
        <a href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/">crypto-lab-dilithium-seal</a> &middot;
        <a href="https://systemslibrarian.github.io/crypto-lab-pq-rotation/">crypto-lab-pq-rotation</a> &middot;
        <a href="https://systemslibrarian.github.io/crypto-lab-kerberos/">crypto-lab-kerberos</a></p>
      <p>So whether you eat or drink or whatever you do, do it all for the glory of God. &mdash; 1 Corinthians 10:31</p>
    </footer>
  `;
}

async function resetLab(state: AppState): Promise<void> {
  state.tamperedNodes.clear();
  state.revokeViaCrl = false;
  state.revokeViaOcsp = false;
  state.compromisedCa = null;
  state.trustContext = 'browser';
  state.pqMode = 'classical';
  state.selectedNode = 'leaf';
  state.ctLog = await createCtLog();
  state.latestSct = null;
  state.latestProof = null;
  state.latestProofValid = null;
  state.latestConsistency = null;
  state.latestConsistencyValid = null;
  state.misissuance = null;
  await recomputeValidation(state);
}

function bindEvents(state: AppState): void {
  const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle');
  themeToggle?.addEventListener('click', () => {
    state.theme = state.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = state.theme;
    localStorage.setItem('theme', state.theme);
    render(state);
  });

  document.querySelector<HTMLButtonElement>('#reset-lab')?.addEventListener('click', async () => {
    await resetLab(state);
    render(state);
  });

  document.querySelectorAll<HTMLButtonElement>('[data-select]').forEach((button) => {
    button.addEventListener('click', () => {
      state.selectedNode = button.dataset.select as CertNode;
      render(state);
    });
  });

  document.querySelector<HTMLButtonElement>('#run-validation')?.addEventListener('click', async () => {
    await recomputeValidation(state);
    render(state);
  });

  document.querySelectorAll<HTMLButtonElement>('[data-tamper]').forEach((button) => {
    button.addEventListener('click', async () => {
      const node = button.dataset.tamper as CertNode;
      if (state.tamperedNodes.has(node)) {
        state.tamperedNodes.delete(node);
      } else {
        state.tamperedNodes.add(node);
      }
      state.selectedNode = node;
      await recomputeValidation(state);
      render(state);
    });
  });

  document.querySelector<HTMLInputElement>('#toggle-crl')?.addEventListener('change', async (event) => {
    const input = event.target as HTMLInputElement;
    state.revokeViaCrl = input.checked;
    await recomputeValidation(state);
    render(state);
  });

  document.querySelector<HTMLInputElement>('#toggle-ocsp')?.addEventListener('change', async (event) => {
    const input = event.target as HTMLInputElement;
    state.revokeViaOcsp = input.checked;
    await recomputeValidation(state);
    render(state);
  });

  document.querySelectorAll<HTMLButtonElement>('[data-context]').forEach((button) => {
    button.addEventListener('click', async () => {
      state.trustContext = button.dataset.context as TrustContext;
      await recomputeValidation(state);
      render(state);
    });
  });

  document.querySelectorAll<HTMLButtonElement>('[data-compromise]').forEach((button) => {
    button.addEventListener('click', () => {
      const mode = button.dataset.compromise;
      state.compromisedCa = mode === 'none' ? null : (mode as CompromisedCa);
      render(state);
    });
  });

  document.querySelector<HTMLButtonElement>('#ct-submit')?.addEventListener('click', async () => {
    state.latestSct = await state.ctLog.submitCertificate(state.chain.leaf.cert);
    state.latestProof = null;
    state.latestConsistency = null;
    render(state);
  });

  document.querySelector<HTMLButtonElement>('#ct-proof')?.addEventListener('click', async () => {
    const last = state.ctLog.size - 1;
    if (last < 0) {
      return;
    }
    state.latestProof = await state.ctLog.generateInclusionProof(last);
    state.latestProofValid = await state.ctLog.verifyInclusionProof(state.latestProof);
    render(state);
  });

  document.querySelector<HTMLButtonElement>('#ct-consistency')?.addEventListener('click', async () => {
    if (state.ctLog.size < 2) {
      return;
    }
    state.latestConsistency = await state.ctLog.generateConsistencyProof(state.ctLog.size - 1, state.ctLog.size);
    state.latestConsistencyValid = await state.ctLog.verifyConsistencyProof(state.latestConsistency);
    render(state);
  });

  document.querySelector<HTMLButtonElement>('#ct-misissue')?.addEventListener('click', async () => {
    const forged: Certificate = {
      ...state.chain.leaf.cert,
      issuer: 'CN=Compromised DigiNotar CA',
      serialNumber: `${state.chain.leaf.cert.serialNumber}ff`,
    };

    await state.ctLog.submitCertificate(forged);
    state.misissuance = state.ctLog.detectMisissuance(forged, new Set([state.chain.intermediate.cert.subject]));
    render(state);
  });

  document.querySelectorAll<HTMLButtonElement>('[data-pq]').forEach((button) => {
    button.addEventListener('click', () => {
      state.pqMode = button.dataset.pq as PqMode;
      render(state);
    });
  });
}

function render(state: AppState): void {
  app!.innerHTML = `<main class="page">${exhibitsMarkup(state)}</main>`;
  bindEvents(state);
}

async function init(): Promise<void> {
  const chain = await createDemoChain();
  const browserStore = await createTrustStore(chain.root.cert);
  const rootFingerprint = await trustAnchorFingerprint(chain.root.cert);

  const osStore: TrustStore = { trustedRoots: new Set() };
  const appStore: TrustStore = { trustedRoots: new Set([rootFingerprint]) };

  const theme = (localStorage.getItem('theme') as Theme | null) ?? 'dark';
  document.documentElement.dataset.theme = theme;

  const state: AppState = {
    chain,
    selectedNode: 'leaf',
    validation: null,
    trustStores: {
      browser: browserStore,
      os: osStore,
      application: appStore,
    },
    trustContext: 'browser',
    tamperedNodes: new Set<CertNode>(),
    revokeViaCrl: false,
    revokeViaOcsp: false,
    compromisedCa: null,
    ctLog: await createCtLog(),
    latestSct: null,
    latestProof: null,
    latestProofValid: null,
    latestConsistency: null,
    latestConsistencyValid: null,
    misissuance: null,
    theme,
    pqMode: 'classical',
    rootFingerprint,
  };

  await recomputeValidation(state);
  render(state);
}

void init();
