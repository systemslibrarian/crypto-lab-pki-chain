(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const i of document.querySelectorAll('link[rel="modulepreload"]'))a(i);new MutationObserver(i=>{for(const o of i)if(o.type==="childList")for(const s of o.addedNodes)s.tagName==="LINK"&&s.rel==="modulepreload"&&a(s)}).observe(document,{childList:!0,subtree:!0});function r(i){const o={};return i.integrity&&(o.integrity=i.integrity),i.referrerPolicy&&(o.referrerPolicy=i.referrerPolicy),i.crossOrigin==="use-credentials"?o.credentials="include":i.crossOrigin==="anonymous"?o.credentials="omit":o.credentials="same-origin",o}function a(i){if(i.ep)return;i.ep=!0;const o=r(i);fetch(i.href,o)}})();function K(e){return Array.from(new Uint8Array(e),t=>t.toString(16).padStart(2,"0")).join("")}function E(e){if(e.length%2!==0)throw new Error("Invalid hex input.");const t=new Uint8Array(e.length/2);for(let r=0;r<t.length;r+=1)t[r]=Number.parseInt(e.slice(r*2,r*2+2),16);return t}function q(...e){const t=e.reduce((i,o)=>i+o.length,0),r=new Uint8Array(t);let a=0;for(const i of e)r.set(i,a),a+=i.length;return r}async function C(e){const t=await crypto.subtle.digest("SHA-256",e);return K(t)}function z(e){const t=JSON.stringify({subject:e.subject,issuer:e.issuer,publicKey:e.publicKey,validFrom:e.validFrom,validTo:e.validTo,serialNumber:e.serialNumber,signature:K(e.signature)});return new TextEncoder().encode(t)}async function U(e){const t=q(new Uint8Array([0]),e);return C(t)}async function P(e,t){const r=q(new Uint8Array([1]),E(e),E(t));return C(r)}async function D(e){if(e.length===0)return[{hashes:[]}];const t=[{hashes:e.slice()}];for(;t[t.length-1].hashes.length>1;){const r=t[t.length-1].hashes,a=[];for(let i=0;i<r.length;i+=2){const o=r[i],s=r[i+1]??r[i];a.push(await P(o,s))}t.push({hashes:a})}return t}async function w(e){if(e.length===0)return C(new Uint8Array([255]));const t=await D(e);return t[t.length-1].hashes[0]}async function W(e,t,r){const a=new TextEncoder().encode(`${r}:${t}`),i=await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},e.keyPair.privateKey,a);return{logId:e.logId,timestamp:r,entryHash:t,signature:i,algorithm:"ECDSA_P256_SHA256"}}async function G(){const e=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},!0,["sign","verify"]),t=await crypto.subtle.exportKey("spki",e.publicKey),r=await C(new Uint8Array(t)),a={keyPair:e,logId:r,leaves:[]};return{get size(){return a.leaves.length},get logId(){return a.logId},get leaves(){return a.leaves},async submitCertificate(i){const o=Date.now(),s=z(i),c=await U(s);return a.leaves.push({certificate:i,certHash:c,timestamp:o}),W(a,c,o)},async rootHash(){return w(a.leaves.map(i=>i.certHash))},async generateInclusionProof(i,o=a.leaves.length){if(o<1||o>a.leaves.length)throw new Error("Tree size out of range.");if(i<0||i>=o)throw new Error("Leaf index out of range for requested tree size.");const s=a.leaves.slice(0,o).map(p=>p.certHash),c=await D(s),u=[];let n=i;for(let p=0;p<c.length-1;p+=1){const f=c[p].hashes,y=n%2===0,g=y?n+1:n-1,v=f[g]??f[n];u.push({hash:v,position:y?"right":"left"}),n=Math.floor(n/2)}const l=s[i],m=c[c.length-1].hashes[0];return{leafIndex:i,treeSize:o,leafHash:l,auditPath:u,rootHash:m}},async verifyInclusionProof(i){let o=i.leafHash;for(const s of i.auditPath)s.position==="left"?o=await P(s.hash,o):o=await P(o,s.hash);return o===i.rootHash},async generateConsistencyProof(i,o){if(i<1||o<1)throw new Error("Tree sizes must be at least 1.");if(i>o)throw new Error("Old tree size must be <= new tree size.");if(o>a.leaves.length)throw new Error("Requested size exceeds current log size.");const s=a.leaves.slice(0,o).map(n=>n.certHash),c=await w(s.slice(0,i)),u=await w(s);return{oldSize:i,newSize:o,oldRoot:c,newRoot:u,leavesForNewTree:s}},async verifyConsistencyProof(i){if(i.oldSize>i.newSize||i.leavesForNewTree.length!==i.newSize)return!1;const o=await w(i.leavesForNewTree.slice(0,i.oldSize)),s=await w(i.leavesForNewTree);return o===i.oldRoot&&s===i.newRoot},detectMisissuance(i,o){return o.size===0?{suspicious:!1,reason:"No issuer policy provided for this subject."}:o.has(i.issuer)?{suspicious:!1,reason:"Issuer matches expected issuance policy."}:{suspicious:!0,reason:`Issuer ${i.issuer} is outside expected policy for ${i.subject}.`}}}}const S={name:"ECDSA",namedCurve:"P-256"},M={name:"ECDSA",hash:"SHA-256"};function Q(){const e=new Uint8Array(12);return crypto.getRandomValues(e),Array.from(e,t=>t.toString(16).padStart(2,"0")).join("")}function O(e){const t=new Uint8Array(e);let r="";for(const a of t)r+=String.fromCharCode(a);return btoa(r).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function F(e){return JSON.stringify({subject:e.subject,issuer:e.issuer,publicKey:e.publicKey,validFrom:e.validFrom,validTo:e.validTo,serialNumber:e.serialNumber})}function A(e){return new TextEncoder().encode(F({subject:e.subject,issuer:e.issuer,publicKey:e.publicKey,validFrom:e.validFrom,validTo:e.validTo,serialNumber:e.serialNumber}))}async function _(e,t){const r=new TextEncoder().encode(F(e)),a=await crypto.subtle.sign(M,t,r);return{...e,signature:a}}async function $(e,t){const r=A(e);return crypto.subtle.verify(M,t,e.signature,r)}function j(e,t=new Date){const r=new Date(e.validFrom),a=new Date(e.validTo);return t>=r&&t<=a}async function k(e,t,r,a,i,o){const s=await crypto.subtle.exportKey("jwk",r);return _({subject:e,issuer:t,publicKey:s,validFrom:i.toISOString(),validTo:o.toISOString(),serialNumber:Q()},a)}function b(e,t,r,a){e.push({label:t,ok:r,details:a})}async function J(){const e=new Date,t=new Date(e);t.setFullYear(e.getFullYear()+1);const r=await crypto.subtle.generateKey(S,!0,["sign","verify"]),a=await crypto.subtle.generateKey(S,!0,["sign","verify"]),i=await crypto.subtle.generateKey(S,!0,["sign","verify"]),o=await k("CN=Crypto Lab Root CA","CN=Crypto Lab Root CA",r.publicKey,r.privateKey,e,t),s=await k("CN=Crypto Lab Intermediate CA",o.subject,a.publicKey,r.privateKey,e,t),c=await k("CN=demo.crypto-lab.local",s.subject,i.publicKey,a.privateKey,e,t);return{root:{cert:o,keyPair:r},intermediate:{cert:s,keyPair:a},leaf:{cert:c,keyPair:i}}}async function Y(e){const t=await crypto.subtle.digest("SHA-256",A(e));return{trustedRoots:new Set([O(t)])}}async function H(e){const t=A(e),r=await crypto.subtle.digest("SHA-256",t);return O(r)}async function X(e,t,r=[],a=[]){const i=[],o=j(e.root.cert);b(i,"Root validity window",o,o?"Root certificate is within validity period.":"Root certificate is expired or not yet valid.");const s=await $(e.root.cert,e.root.keyPair.publicKey);b(i,"Root self-signature",s,s?"Root self-signature verifies.":"Root self-signature verification failed.");const c=e.intermediate.cert.issuer===e.root.cert.subject;b(i,"Intermediate issuer linkage",c,c?"Intermediate issuer matches root subject.":"Intermediate issuer does not match root subject.");const u=await $(e.intermediate.cert,e.root.keyPair.publicKey);b(i,"Intermediate signature",u,u?"Intermediate certificate signature verifies against root key.":"Intermediate signature is invalid.");const n=e.leaf.cert.issuer===e.intermediate.cert.subject;b(i,"Leaf issuer linkage",n,n?"Leaf issuer matches intermediate subject.":"Leaf issuer does not match intermediate subject.");const l=await $(e.leaf.cert,e.intermediate.keyPair.publicKey);b(i,"Leaf signature",l,l?"Leaf certificate signature verifies against intermediate key.":"Leaf signature is invalid.");const m=j(e.leaf.cert);b(i,"Leaf validity window",m,m?"Leaf certificate is within validity period.":"Leaf certificate is expired or not yet valid.");const p=await H(e.root.cert),f=t.trustedRoots.has(p);b(i,"Trust anchor check",f,f?"Root certificate exists in selected trust store.":"Root certificate is missing from trust store.");const y=I(e.leaf.cert,r)||I(e.intermediate.cert,r);b(i,"CRL revocation check",!y,y?"A certificate serial appears in a CRL.":"No certificate serial present in supplied CRLs.");const g=R(e.leaf.cert,a),v=R(e.intermediate.cert,a),T=g!=="revoked"&&v!=="revoked";return b(i,"OCSP revocation check",T,T?`OCSP statuses: leaf=${g}, intermediate=${v}.`:`OCSP revoked status detected: leaf=${g}, intermediate=${v}.`),{ok:i.every(B=>B.ok),steps:i}}function Z(e,t=[]){return{issuer:e,revokedSerialNumbers:new Set(t)}}function ee(e,t=[]){return{issuer:e,statusBySerial:new Map(t.map(r=>[r.serialNumber,r.status]))}}function I(e,t){for(const r of t)if(r.issuer===e.issuer&&r.revokedSerialNumbers.has(e.serialNumber))return!0;return!1}function R(e,t){for(const r of t)if(r.issuer===e.issuer)return r.statusBySerial.get(e.serialNumber)??"unknown";return"unknown"}function te(e,t){const r=new Set;return t?t==="root"?(r.add(e.root.cert.subject),r.add(e.intermediate.cert.subject),r.add(e.leaf.cert.subject),r):(r.add(e.intermediate.cert.subject),r.add(e.leaf.cert.subject),r):r}const V=document.querySelector("#app");if(!V)throw new Error("Missing app root element.");function L(e,t=12){return e.length>t*2?`${e.slice(0,t)}...${e.slice(-t)}`:e}function x(e){return e.replace("CN=","")}function ie(e,t){return t==="root"?e.chain.root.cert:t==="intermediate"?e.chain.intermediate.cert:e.chain.leaf.cert}function N(e){return{...e,subject:`${e.subject} [tampered]`}}async function h(e){const t=e.revokeViaCrl?[Z(e.chain.leaf.cert.issuer,[e.chain.leaf.cert.serialNumber])]:[],r=e.revokeViaOcsp?[ee(e.chain.leaf.cert.issuer,[{serialNumber:e.chain.leaf.cert.serialNumber,status:"revoked"}])]:[];e.validation=await X(e.chain,e.trustStores[e.trustContext],t,r)}function re(e){var s,c,u,n,l,m;const t=ie(e,e.selectedNode),r=te(e.chain,e.compromisedCa),a=((s=e.validation)==null?void 0:s.ok)??!1,i=t.signature.byteLength,o={classical:{title:"Classical P-256 Chain",alg:"ECDSA P-256",sigBytes:"64-72 bytes",keyBytes:"65 bytes public key",note:"Current web PKI baseline with broad browser and HSM support."},mldsa:{title:"Post-Quantum ML-DSA Chain",alg:"ML-DSA (Dilithium family)",sigBytes:"~2,420 bytes",keyBytes:"~1,312 bytes public key",note:"Stronger against quantum adversaries but larger artifacts and ecosystem rollout risk."},hybrid:{title:"Hybrid Transition Chain",alg:"ECDSA + ML-DSA dual signatures",sigBytes:"Classical + PQ total",keyBytes:"Dual key material",note:"Preferred migration path: maintain compatibility while adding PQ assurance."}}[e.pqMode];return`
    <header class="hero panel" role="banner">
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to ${e.theme==="dark"?"light":"dark"} mode">
        <span aria-hidden="true">${e.theme==="dark"?"☀️":"🌙"}</span>
        <span class="sr-only">${e.theme==="dark"?"Light":"Dark"} mode</span>
      </button>
      <p class="eyebrow" aria-hidden="true">crypto-lab interactive exhibit</p>
      <h1>PKI Chain, Trust, and CT</h1>
      <p class="lede">Explore certificate chain trust, CA failure blast radius, and Certificate Transparency monitoring in one browser-native lab.</p>
    </header>

    <section class="panel exhibit" id="exhibit-1" aria-labelledby="ex1-heading">
      <h2 id="ex1-heading">Exhibit 1 &mdash; The Chain</h2>
      <p class="caption">Root CA &rarr; Intermediate CA &rarr; Leaf certificate with trust propagation from anchor to endpoint.</p>
      <div class="chain-row ${a?"trust-flow-on":""}" role="group" aria-label="Certificate chain">
        <button type="button" class="cert-chip ${e.selectedNode==="root"?"active":""} ${r.has(e.chain.root.cert.subject)?"compromised":""}" data-select="root" aria-pressed="${e.selectedNode==="root"}" aria-label="Root CA certificate${r.has(e.chain.root.cert.subject)?", compromised":""}">Root CA</button>
        <span class="arrow" aria-hidden="true">&rarr;</span>
        <button type="button" class="cert-chip ${e.selectedNode==="intermediate"?"active":""} ${r.has(e.chain.intermediate.cert.subject)?"compromised":""}" data-select="intermediate" aria-pressed="${e.selectedNode==="intermediate"}" aria-label="Intermediate CA certificate${r.has(e.chain.intermediate.cert.subject)?", compromised":""}">Intermediate</button>
        <span class="arrow" aria-hidden="true">&rarr;</span>
        <button type="button" class="cert-chip ${e.selectedNode==="leaf"?"active":""} ${r.has(e.chain.leaf.cert.subject)?"compromised":""}" data-select="leaf" aria-pressed="${e.selectedNode==="leaf"}" aria-label="Leaf certificate${r.has(e.chain.leaf.cert.subject)?", compromised":""}">Leaf</button>
      </div>
      <div class="cert-inspector" role="region" aria-label="Certificate details for ${e.selectedNode}" aria-live="polite">
        <dl class="cert-fields">
          <dt>Subject</dt><dd>${t.subject}</dd>
          <dt>Issuer</dt><dd>${t.issuer}</dd>
          <dt>Serial</dt><dd><span class="mono">${t.serialNumber}</span></dd>
          <dt>Validity</dt><dd>${new Date(t.validFrom).toLocaleDateString()} &ndash; ${new Date(t.validTo).toLocaleDateString()}</dd>
          <dt>Public Key</dt><dd>${t.publicKey.kty??"unknown"} / ${t.publicKey.crv??t.publicKey.alg??"n/a"}</dd>
          <dt>Signature Size</dt><dd>${i} bytes</dd>
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
        <label><input id="toggle-crl" type="checkbox" ${e.revokeViaCrl?"checked":""} /> Simulate CRL revocation</label>
        <label><input id="toggle-ocsp" type="checkbox" ${e.revokeViaOcsp?"checked":""} /> Simulate OCSP revoked</label>
      </fieldset>
      <ul class="step-list" aria-label="Validation steps" role="list">
        ${(((c=e.validation)==null?void 0:c.steps)??[]).map(p=>`<li class="${p.ok?"pass":"fail"}" aria-label="${p.label}: ${p.ok?"passed":"failed"}"><strong>${p.label}:</strong> ${p.details}</li>`).join("")}
      </ul>
      <p class="status ${(u=e.validation)!=null&&u.ok?"pass":"fail"}" role="status" aria-live="polite">Overall: ${(n=e.validation)!=null&&n.ok?"PASS":"FAIL"}</p>
    </section>

    <section class="panel exhibit" id="exhibit-3" aria-labelledby="ex3-heading">
      <h2 id="ex3-heading">Exhibit 3 &mdash; Trust Stores</h2>
      <p class="caption">The same chain can be accepted or rejected depending on browser, OS, or app trust roots.</p>
      <div class="tab-row" role="tablist" aria-label="Trust store context">
        <button class="tab ${e.trustContext==="browser"?"active":""}" data-context="browser" type="button" role="tab" aria-selected="${e.trustContext==="browser"}">Browser Store</button>
        <button class="tab ${e.trustContext==="os"?"active":""}" data-context="os" type="button" role="tab" aria-selected="${e.trustContext==="os"}">OS Store</button>
        <button class="tab ${e.trustContext==="application"?"active":""}" data-context="application" type="button" role="tab" aria-selected="${e.trustContext==="application"}">Application Store</button>
      </div>
      <p>Current context: <strong>${e.trustContext}</strong></p>
      <p>Root fingerprint: <span class="mono">${L(e.rootFingerprint,18)}</span></p>
      <p>Context trust decision: <strong>${(l=e.validation)!=null&&l.ok?"Trusted":"Rejected"}</strong></p>
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
        <button class="tab ${e.compromisedCa===null?"active":""}" data-compromise="none" type="button" role="tab" aria-selected="${e.compromisedCa===null}">No Compromise</button>
        <button class="tab ${e.compromisedCa==="intermediate"?"active":""}" data-compromise="intermediate" type="button" role="tab" aria-selected="${e.compromisedCa==="intermediate"}">Intermediate Compromised</button>
        <button class="tab ${e.compromisedCa==="root"?"active":""}" data-compromise="root" type="button" role="tab" aria-selected="${e.compromisedCa==="root"}">Root Compromised</button>
      </div>
      <p>Untrusted subtree:</p>
      <ul class="subtree-list" aria-live="polite">
        <li class="${r.has(e.chain.root.cert.subject)?"fail":"pass"}">${x(e.chain.root.cert.subject)}</li>
        <li class="${r.has(e.chain.intermediate.cert.subject)?"fail":"pass"}">${x(e.chain.intermediate.cert.subject)}</li>
        <li class="${r.has(e.chain.leaf.cert.subject)?"fail":"pass"}">${x(e.chain.leaf.cert.subject)}</li>
      </ul>
      <p class="incident-note"><strong>DigiNotar 2011:</strong> attacker-issued fraudulent certificates (including google.com), prompting browser vendors to distrust the CA and break trust for all descendants.</p>
    </section>

    <section class="panel exhibit" id="exhibit-5" aria-labelledby="ex5-heading">
      <h2 id="ex5-heading">Exhibit 5 &mdash; Certificate Transparency</h2>
      <p class="caption">Submit certificates to a simulated append-only log, mint SCTs, verify inclusion, and catch misissuance.</p>
      <div class="control-row">
        <button id="ct-submit" class="btn" type="button">Submit Leaf to CT Log</button>
        <button id="ct-proof" class="btn ghost" type="button" ${e.ctLog.size<1?"disabled":""}>Inclusion Proof</button>
        <button id="ct-consistency" class="btn ghost" type="button" ${e.ctLog.size<2?"disabled":""}>Consistency Proof</button>
        <button id="ct-misissue" class="btn danger" type="button">Simulate Misissuance</button>
      </div>
      <p>Log size: <strong>${e.ctLog.size}</strong> | Log ID: <span class="mono">${L(e.ctLog.logId,14)}</span></p>
      <p>SCT: ${e.latestSct?`<span class="mono">${L(e.latestSct.entryHash,14)}</span> at ${new Date(e.latestSct.timestamp).toLocaleTimeString()}`:"No SCT generated yet."}</p>
      <p>Inclusion proof: ${e.latestProof?`${e.latestProof.auditPath.length} sibling hashes, verify=${e.latestProofValid?"true":"false"}`:"Not generated."}</p>
      <p>Consistency proof: ${e.latestConsistency?`old=${e.latestConsistency.oldSize}, new=${e.latestConsistency.newSize}, verify=${e.latestConsistencyValid?"true":"false"}`:"Not generated."}</p>
      <p class="status ${(m=e.misissuance)!=null&&m.suspicious?"fail":"pass"}" role="status" aria-live="polite">Misissuance monitor: ${e.misissuance?e.misissuance.reason:"No suspicious issuance observed."}</p>
      <p class="incident-note">CT bridge: Merkle proofs from this panel mirror the trust model used by public browser CT logs.</p>
    </section>

    <section class="panel exhibit" id="exhibit-6" aria-labelledby="ex6-heading">
      <h2 id="ex6-heading">Exhibit 6 &mdash; PQ Migration</h2>
      <p class="caption">Compare classical and post-quantum certificate chain signatures and migration strategy.</p>
      <div class="tab-row" role="tablist" aria-label="Post-quantum algorithm selection">
        <button class="tab ${e.pqMode==="classical"?"active":""}" data-pq="classical" type="button" role="tab" aria-selected="${e.pqMode==="classical"}">P-256</button>
        <button class="tab ${e.pqMode==="mldsa"?"active":""}" data-pq="mldsa" type="button" role="tab" aria-selected="${e.pqMode==="mldsa"}">ML-DSA</button>
        <button class="tab ${e.pqMode==="hybrid"?"active":""}" data-pq="hybrid" type="button" role="tab" aria-selected="${e.pqMode==="hybrid"}">Hybrid</button>
      </div>
      <h3>${o.title}</h3>
      <p><strong>Algorithm:</strong> ${o.alg}</p>
      <p><strong>Signature footprint:</strong> ${o.sigBytes}</p>
      <p><strong>Public key footprint:</strong> ${o.keyBytes}</p>
      <p>${o.note}</p>
      <p class="incident-note">Compatibility note: browsers currently validate classical WebPKI signatures; PQ rollouts are expected to use hybrid certificates first.</p>
    </section>

    <footer class="panel footer-note" role="contentinfo">
      <p>So whether you eat or drink or whatever you do, do it all for the glory of God. &mdash; 1 Corinthians 10:31</p>
    </footer>
  `}function oe(e){var r,a,i,o,s,c,u;const t=document.querySelector("#theme-toggle");t==null||t.addEventListener("click",()=>{e.theme=e.theme==="dark"?"light":"dark",document.documentElement.dataset.theme=e.theme,localStorage.setItem("crypto-lab-theme",e.theme),d(e)}),document.querySelectorAll("[data-select]").forEach(n=>{n.addEventListener("click",()=>{e.selectedNode=n.dataset.select,d(e)})}),(r=document.querySelector("#run-validation"))==null||r.addEventListener("click",async()=>{await h(e),d(e)}),document.querySelectorAll("[data-tamper]").forEach(n=>{n.addEventListener("click",async()=>{const l=n.dataset.tamper;l==="root"?e.chain.root.cert=N(e.chain.root.cert):l==="intermediate"?e.chain.intermediate.cert=N(e.chain.intermediate.cert):e.chain.leaf.cert=N(e.chain.leaf.cert),e.tamperedNodes.add(l),await h(e),d(e)})}),(a=document.querySelector("#toggle-crl"))==null||a.addEventListener("change",async n=>{const l=n.target;e.revokeViaCrl=l.checked,await h(e),d(e)}),(i=document.querySelector("#toggle-ocsp"))==null||i.addEventListener("change",async n=>{const l=n.target;e.revokeViaOcsp=l.checked,await h(e),d(e)}),document.querySelectorAll("[data-context]").forEach(n=>{n.addEventListener("click",async()=>{e.trustContext=n.dataset.context,await h(e),d(e)})}),document.querySelectorAll("[data-compromise]").forEach(n=>{n.addEventListener("click",()=>{const l=n.dataset.compromise;e.compromisedCa=l==="none"?null:l,d(e)})}),(o=document.querySelector("#ct-submit"))==null||o.addEventListener("click",async()=>{e.latestSct=await e.ctLog.submitCertificate(e.chain.leaf.cert),e.latestProof=null,e.latestConsistency=null,d(e)}),(s=document.querySelector("#ct-proof"))==null||s.addEventListener("click",async()=>{const n=e.ctLog.size-1;n<0||(e.latestProof=await e.ctLog.generateInclusionProof(n),e.latestProofValid=await e.ctLog.verifyInclusionProof(e.latestProof),d(e))}),(c=document.querySelector("#ct-consistency"))==null||c.addEventListener("click",async()=>{e.ctLog.size<2||(e.latestConsistency=await e.ctLog.generateConsistencyProof(e.ctLog.size-1,e.ctLog.size),e.latestConsistencyValid=await e.ctLog.verifyConsistencyProof(e.latestConsistency),d(e))}),(u=document.querySelector("#ct-misissue"))==null||u.addEventListener("click",async()=>{const n={...e.chain.leaf.cert,issuer:"CN=Compromised DigiNotar CA",serialNumber:`${e.chain.leaf.cert.serialNumber}ff`};await e.ctLog.submitCertificate(n),e.misissuance=e.ctLog.detectMisissuance(n,new Set([e.chain.intermediate.cert.subject])),d(e)}),document.querySelectorAll("[data-pq]").forEach(n=>{n.addEventListener("click",()=>{e.pqMode=n.dataset.pq,d(e)})})}function d(e){V.innerHTML=`<main class="page">${re(e)}</main>`,oe(e)}async function ae(){const e=await J(),t=await Y(e.root.cert),r=await H(e.root.cert),a={trustedRoots:new Set},i={trustedRoots:new Set([r])},o=localStorage.getItem("crypto-lab-theme")??"dark";document.documentElement.dataset.theme=o;const s={chain:e,selectedNode:"leaf",validation:null,trustStores:{browser:t,os:a,application:i},trustContext:"browser",tamperedNodes:new Set,revokeViaCrl:!1,revokeViaOcsp:!1,compromisedCa:null,ctLog:await G(),latestSct:null,latestProof:null,latestProofValid:null,latestConsistency:null,latestConsistencyValid:null,misissuance:null,theme:o,pqMode:"classical",rootFingerprint:r};await h(s),d(s)}ae();
