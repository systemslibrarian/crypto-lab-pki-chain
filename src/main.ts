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

function shortHex(value: string, count = 12): string {
  return value.length > count * 2 ? `${value.slice(0, count)}...${value.slice(-count)}` : value;
}

function shortSubject(value: string): string {
  return value.replace('CN=', '');
}

function certAt(state: AppState, node: CertNode): Certificate {
  if (node === 'root') {
    return state.chain.root.cert;
  }
  if (node === 'intermediate') {
    return state.chain.intermediate.cert;
  }
  return state.chain.leaf.cert;
}

function mutateCertificateForTamper(cert: Certificate): Certificate {
  return {
    ...cert,
    subject: `${cert.subject} [tampered]`,
  };
}

async function recomputeValidation(state: AppState): Promise<void> {
  const crls = state.revokeViaCrl
    ? [createCrl(state.chain.leaf.cert.issuer, [state.chain.leaf.cert.serialNumber])]
    : [];

  const ocsp = state.revokeViaOcsp
    ? [
        createOcspResponder(state.chain.leaf.cert.issuer, [
          { serialNumber: state.chain.leaf.cert.serialNumber, status: 'revoked' },
        ]),
      ]
    : [];

  state.validation = await validateChain(
    state.chain,
    state.trustStores[state.trustContext],
    crls,
    ocsp,
  );
}

function exhibitsMarkup(state: AppState): string {
  const selected = certAt(state, state.selectedNode);
  const compromiseSet = compromisedSubtree(state.chain, state.compromisedCa);
  const chainTrusted = state.validation?.ok ?? false;
  const signatureBytes = selected.signature.byteLength;

  const pqInfo = {
    classical: {
      title: 'Classical P-256 Chain',
      alg: 'ECDSA P-256',
      sigBytes: '64-72 bytes',
      keyBytes: '65 bytes public key',
      note: 'Current web PKI baseline with broad browser and HSM support.',
    },
    mldsa: {
      title: 'Post-Quantum ML-DSA Chain',
      alg: 'ML-DSA (Dilithium family)',
      sigBytes: '~2,420 bytes',
      keyBytes: '~1,312 bytes public key',
      note: 'Stronger against quantum adversaries but larger artifacts and ecosystem rollout risk.',
    },
    hybrid: {
      title: 'Hybrid Transition Chain',
      alg: 'ECDSA + ML-DSA dual signatures',
      sigBytes: 'Classical + PQ total',
      keyBytes: 'Dual key material',
      note: 'Preferred migration path: maintain compatibility while adding PQ assurance.',
    },
  }[state.pqMode];

  return `
    <header class="hero panel" role="banner">
      <button id="theme-toggle" class="theme-toggle" type="button" style="position: absolute; top: 0; right: 0" aria-label="Switch to ${state.theme === 'dark' ? 'light' : 'dark'} mode">
        <span aria-hidden="true">${state.theme === 'dark' ? '🌙' : '☀️'}</span>
      </button>
      <p class="eyebrow" aria-hidden="true">crypto-lab interactive exhibit</p>
      <h1>PKI Chain, Trust, and CT</h1>
      <p class="lede">Explore certificate chain trust, CA failure blast radius, and Certificate Transparency monitoring in one browser-native lab.</p>
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
    </section>

    <section class="panel exhibit" id="exhibit-2" aria-labelledby="ex2-heading">
      <h2 id="ex2-heading">Exhibit 2 &mdash; Chain Validation</h2>
      <p class="caption">Real WebCrypto signature verification at every link, plus trust anchor and revocation checks.</p>
      <div class="control-row" role="toolbar" aria-label="Validation controls">
        <button id="run-validation" class="btn" type="button">Run Validation</button>
        <button class="btn ghost" data-tamper="root" type="button" aria-label="Tamper with root certificate">Tamper Root</button>
        <button class="btn ghost" data-tamper="intermediate" type="button" aria-label="Tamper with intermediate certificate">Tamper Intermediate</button>
        <button class="btn ghost" data-tamper="leaf" type="button" aria-label="Tamper with leaf certificate">Tamper Leaf</button>
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
      <p>Context trust decision: <strong>${state.validation?.ok ? 'Trusted' : 'Rejected'}</strong></p>
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
      <p>Inclusion proof: ${state.latestProof ? `${state.latestProof.auditPath.length} sibling hashes, verify=${state.latestProofValid ? 'true' : 'false'}` : 'Not generated.'}</p>
      <p>Consistency proof: ${state.latestConsistency ? `old=${state.latestConsistency.oldSize}, new=${state.latestConsistency.newSize}, verify=${state.latestConsistencyValid ? 'true' : 'false'}` : 'Not generated.'}</p>
      <p class="status ${state.misissuance?.suspicious ? 'fail' : 'pass'}" role="status" aria-live="polite">Misissuance monitor: ${state.misissuance ? state.misissuance.reason : 'No suspicious issuance observed.'}</p>
      <p class="incident-note">CT bridge: Merkle proofs from this panel mirror the trust model used by public browser CT logs.</p>
    </section>

    <section class="panel exhibit" id="exhibit-6" aria-labelledby="ex6-heading">
      <h2 id="ex6-heading">Exhibit 6 &mdash; PQ Migration</h2>
      <p class="caption">Compare classical and post-quantum certificate chain signatures and migration strategy.</p>
      <div class="tab-row" role="tablist" aria-label="Post-quantum algorithm selection">
        <button class="tab ${state.pqMode === 'classical' ? 'active' : ''}" data-pq="classical" type="button" role="tab" aria-selected="${state.pqMode === 'classical'}">P-256</button>
        <button class="tab ${state.pqMode === 'mldsa' ? 'active' : ''}" data-pq="mldsa" type="button" role="tab" aria-selected="${state.pqMode === 'mldsa'}">ML-DSA</button>
        <button class="tab ${state.pqMode === 'hybrid' ? 'active' : ''}" data-pq="hybrid" type="button" role="tab" aria-selected="${state.pqMode === 'hybrid'}">Hybrid</button>
      </div>
      <h3>${pqInfo.title}</h3>
      <p><strong>Algorithm:</strong> ${pqInfo.alg}</p>
      <p><strong>Signature footprint:</strong> ${pqInfo.sigBytes}</p>
      <p><strong>Public key footprint:</strong> ${pqInfo.keyBytes}</p>
      <p>${pqInfo.note}</p>
      <p class="incident-note">Compatibility note: browsers currently validate classical WebPKI signatures; PQ rollouts are expected to use hybrid certificates first.</p>
    </section>

    <footer class="panel footer-note" role="contentinfo">
      <p>So whether you eat or drink or whatever you do, do it all for the glory of God. &mdash; 1 Corinthians 10:31</p>
    </footer>
  `;
}

function bindEvents(state: AppState): void {
  const themeToggle = document.querySelector<HTMLButtonElement>('#theme-toggle');
  themeToggle?.addEventListener('click', () => {
    state.theme = state.theme === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = state.theme;
    localStorage.setItem('theme', state.theme);
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
      if (node === 'root') {
        state.chain.root.cert = mutateCertificateForTamper(state.chain.root.cert);
      } else if (node === 'intermediate') {
        state.chain.intermediate.cert = mutateCertificateForTamper(state.chain.intermediate.cert);
      } else {
        state.chain.leaf.cert = mutateCertificateForTamper(state.chain.leaf.cert);
      }

      state.tamperedNodes.add(node);
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
  app.innerHTML = `<main class="page">${exhibitsMarkup(state)}</main>`;
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
