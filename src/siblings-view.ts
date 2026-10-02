import { runSiblingCompromise } from './siblings';
export function siblingsView(onChange: () => void): HTMLElement {
  const panel = document.createElement('section');
  panel.id = 'sibling-lab';
  panel.innerHTML = `<h3>Does an intact sibling CA protect its users?</h3>
    <p>One root signs Intermediate A and Intermediate B. Steal only A’s signing key and mint a new certificate for B’s hostname. B’s real key and certificate stay intact.</p>
    <label for="sibling-policy">Intermediate A’s root-signed permission</label>
    <select class="btn" id="sibling-policy"><option value="constrained">Only a.demo.test and its subdomains</option><option value="unconstrained">Any DNS name (deliberately vulnerable)</option></select>
    <button class="btn" id="sibling-run" type="button">Attempt sibling impersonation</button>
    <div id="sibling-result" role="status" aria-live="polite">Not run.</div>
    <p>This is a DNS-only teaching validator over signed JSON, not X.509 DER or complete RFC 5280 validation. Clients trust the shared root and have not yet revoked A. Issuer-tree reachability is a policy view, not the set of stolen keys or impersonable identities.</p>`;
  const select = panel.querySelector<HTMLSelectElement>('select')!;
  const button = panel.querySelector<HTMLButtonElement>('button')!;
  const result = panel.querySelector<HTMLElement>('#sibling-result')!;
  let previous = select.value;
  select.addEventListener('change', () => { if (previous !== select.value) { result.textContent = 'Previous results retired. Run the new constraint policy.'; onChange(); } previous = select.value; });
  button.addEventListener('click', async () => {
    onChange();
    button.disabled = true; select.disabled = true;
    result.textContent = 'Issuing and validating real P-256 signatures…';
    try {
      const r = await runSiblingCompromise(select.value === 'constrained');
      const signature = r.attack.path.steps.find(s => s.label === 'Leaf signature')?.ok;
      result.innerHTML = `<ul>${r.nodes.map(n => `<li>${n.subject} — issuer: ${n.issuer}; key ${n.keyStolen ? 'STOLEN' : 'not stolen'}; ${n.inSubtree ? 'inside' : 'outside'} A’s issued subtree.</li>`).join('')}</ul>
        <p>A’s legitimate identity: ${r.own.accepted ? 'ACCEPTED' : 'REJECTED'}. B’s legitimate identity: ${r.legitimate.accepted ? 'ACCEPTED' : 'REJECTED'}.</p>
        <p>Forged leaf signature: ${signature ? 'VERIFIED' : 'FAILED'}. Chain checks: ${r.attack.path.ok ? 'PASS' : 'FAIL'}. Requested hostname: ${r.attack.hostnameMatches ? 'MATCH' : 'MISMATCH'}. Root-signed name constraint: ${r.attack.namePermitted ? 'PERMITS' : 'REJECTS'}.</p>
        <p class="${r.attack.accepted ? 'fail' : 'pass'}">Attacker identity: ${r.attack.accepted ? 'ACCEPTED — IMPERSONATION' : 'REJECTED'}.</p>
        <p>B’s private key was never needed. An intact sibling key does not prevent impersonation through an unconstrained trusted issuer. Name constraints must be signed by the issuer and enforced by the client.</p>`;
    } catch { result.textContent = 'Experiment failed to run; no security verdict is available.'; }
    finally { button.disabled = false; select.disabled = false; }
  });
  return panel;
}
