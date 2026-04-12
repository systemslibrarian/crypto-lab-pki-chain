(function(){const t=document.createElement("link").relList;if(t&&t.supports&&t.supports("modulepreload"))return;for(const r of document.querySelectorAll('link[rel="modulepreload"]'))n(r);new MutationObserver(r=>{for(const i of r)if(i.type==="childList")for(const a of i.addedNodes)a.tagName==="LINK"&&a.rel==="modulepreload"&&n(a)}).observe(document,{childList:!0,subtree:!0});function o(r){const i={};return r.integrity&&(i.integrity=r.integrity),r.referrerPolicy&&(i.referrerPolicy=r.referrerPolicy),r.crossOrigin==="use-credentials"?i.credentials="include":r.crossOrigin==="anonymous"?i.credentials="omit":i.credentials="same-origin",i}function n(r){if(r.ep)return;r.ep=!0;const i=o(r);fetch(r.href,i)}})();function R(e){return Array.from(new Uint8Array(e),t=>t.toString(16).padStart(2,"0")).join("")}function T(e){if(e.length%2!==0)throw new Error("Invalid hex input.");const t=new Uint8Array(e.length/2);for(let o=0;o<t.length;o+=1)t[o]=Number.parseInt(e.slice(o*2,o*2+2),16);return t}function D(...e){const t=e.reduce((r,i)=>r+i.length,0),o=new Uint8Array(t);let n=0;for(const r of e)o.set(r,n),n+=r.length;return o}async function C(e){const t=await crypto.subtle.digest("SHA-256",e);return R(t)}function z(e){const t=JSON.stringify({subject:e.subject,issuer:e.issuer,publicKey:e.publicKey,validFrom:e.validFrom,validTo:e.validTo,serialNumber:e.serialNumber,signature:R(e.signature)});return new TextEncoder().encode(t)}async function U(e){const t=D(new Uint8Array([0]),e);return C(t)}async function A(e,t){const o=D(new Uint8Array([1]),T(e),T(t));return C(o)}async function q(e){if(e.length===0)return[{hashes:[]}];const t=[{hashes:e.slice()}];for(;t[t.length-1].hashes.length>1;){const o=t[t.length-1].hashes,n=[];for(let r=0;r<o.length;r+=2){const i=o[r],a=o[r+1]??o[r];n.push(await A(i,a))}t.push({hashes:n})}return t}async function w(e){if(e.length===0)return C(new Uint8Array([255]));const t=await q(e);return t[t.length-1].hashes[0]}async function W(e,t,o){const n=new TextEncoder().encode(`${o}:${t}`),r=await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},e.keyPair.privateKey,n);return{logId:e.logId,timestamp:o,entryHash:t,signature:r,algorithm:"ECDSA_P256_SHA256"}}async function G(){const e=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},!0,["sign","verify"]),t=await crypto.subtle.exportKey("spki",e.publicKey),o=await C(new Uint8Array(t)),n={keyPair:e,logId:o,leaves:[]};return{get size(){return n.leaves.length},get logId(){return n.logId},get leaves(){return n.leaves},async submitCertificate(r){const i=Date.now(),a=z(r),c=await U(a);return n.leaves.push({certificate:r,certHash:c,timestamp:i}),W(n,c,i)},async rootHash(){return w(n.leaves.map(r=>r.certHash))},async generateInclusionProof(r,i=n.leaves.length){if(i<1||i>n.leaves.length)throw new Error("Tree size out of range.");if(r<0||r>=i)throw new Error("Leaf index out of range for requested tree size.");const a=n.leaves.slice(0,i).map(p=>p.certHash),c=await q(a),d=[];let s=r;for(let p=0;p<c.length-1;p+=1){const y=c[p].hashes,h=s%2===0,g=h?s+1:s-1,v=y[g]??y[s];d.push({hash:v,position:h?"right":"left"}),s=Math.floor(s/2)}const l=a[r],m=c[c.length-1].hashes[0];return{leafIndex:r,treeSize:i,leafHash:l,auditPath:d,rootHash:m}},async verifyInclusionProof(r){let i=r.leafHash;for(const a of r.auditPath)a.position==="left"?i=await A(a.hash,i):i=await A(i,a.hash);return i===r.rootHash},async generateConsistencyProof(r,i){if(r<1||i<1)throw new Error("Tree sizes must be at least 1.");if(r>i)throw new Error("Old tree size must be <= new tree size.");if(i>n.leaves.length)throw new Error("Requested size exceeds current log size.");const a=n.leaves.slice(0,i).map(s=>s.certHash),c=await w(a.slice(0,r)),d=await w(a);return{oldSize:r,newSize:i,oldRoot:c,newRoot:d,leavesForNewTree:a}},async verifyConsistencyProof(r){if(r.oldSize>r.newSize||r.leavesForNewTree.length!==r.newSize)return!1;const i=await w(r.leavesForNewTree.slice(0,r.oldSize)),a=await w(r.leavesForNewTree);return i===r.oldRoot&&a===r.newRoot},detectMisissuance(r,i){return i.size===0?{suspicious:!1,reason:"No issuer policy provided for this subject."}:i.has(r.issuer)?{suspicious:!1,reason:"Issuer matches expected issuance policy."}:{suspicious:!0,reason:`Issuer ${r.issuer} is outside expected policy for ${r.subject}.`}}}}const S={name:"ECDSA",namedCurve:"P-256"},M={name:"ECDSA",hash:"SHA-256"};function Q(){const e=new Uint8Array(12);return crypto.getRandomValues(e),Array.from(e,t=>t.toString(16).padStart(2,"0")).join("")}function O(e){const t=new Uint8Array(e);let o="";for(const n of t)o+=String.fromCharCode(n);return btoa(o).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}function F(e){return JSON.stringify({subject:e.subject,issuer:e.issuer,publicKey:e.publicKey,validFrom:e.validFrom,validTo:e.validTo,serialNumber:e.serialNumber})}function x(e){return new TextEncoder().encode(F({subject:e.subject,issuer:e.issuer,publicKey:e.publicKey,validFrom:e.validFrom,validTo:e.validTo,serialNumber:e.serialNumber}))}async function _(e,t){const o=new TextEncoder().encode(F(e)),n=await crypto.subtle.sign(M,t,o);return{...e,signature:n}}async function k(e,t){const o=x(e);return crypto.subtle.verify(M,t,e.signature,o)}function j(e,t=new Date){const o=new Date(e.validFrom),n=new Date(e.validTo);return t>=o&&t<=n}async function L(e,t,o,n,r,i){const a=await crypto.subtle.exportKey("jwk",o);return _({subject:e,issuer:t,publicKey:a,validFrom:r.toISOString(),validTo:i.toISOString(),serialNumber:Q()},n)}function b(e,t,o,n){e.push({label:t,ok:o,details:n})}async function J(){const e=new Date,t=new Date(e);t.setFullYear(e.getFullYear()+1);const o=await crypto.subtle.generateKey(S,!0,["sign","verify"]),n=await crypto.subtle.generateKey(S,!0,["sign","verify"]),r=await crypto.subtle.generateKey(S,!0,["sign","verify"]),i=await L("CN=Crypto Lab Root CA","CN=Crypto Lab Root CA",o.publicKey,o.privateKey,e,t),a=await L("CN=Crypto Lab Intermediate CA",i.subject,n.publicKey,o.privateKey,e,t),c=await L("CN=demo.crypto-lab.local",a.subject,r.publicKey,n.privateKey,e,t);return{root:{cert:i,keyPair:o},intermediate:{cert:a,keyPair:n},leaf:{cert:c,keyPair:r}}}async function Y(e){const t=await crypto.subtle.digest("SHA-256",x(e));return{trustedRoots:new Set([O(t)])}}async function H(e){const t=x(e),o=await crypto.subtle.digest("SHA-256",t);return O(o)}async function X(e,t,o=[],n=[]){const r=[],i=j(e.root.cert);b(r,"Root validity window",i,i?"Root certificate is within validity period.":"Root certificate is expired or not yet valid.");const a=await k(e.root.cert,e.root.keyPair.publicKey);b(r,"Root self-signature",a,a?"Root self-signature verifies.":"Root self-signature verification failed.");const c=e.intermediate.cert.issuer===e.root.cert.subject;b(r,"Intermediate issuer linkage",c,c?"Intermediate issuer matches root subject.":"Intermediate issuer does not match root subject.");const d=await k(e.intermediate.cert,e.root.keyPair.publicKey);b(r,"Intermediate signature",d,d?"Intermediate certificate signature verifies against root key.":"Intermediate signature is invalid.");const s=e.leaf.cert.issuer===e.intermediate.cert.subject;b(r,"Leaf issuer linkage",s,s?"Leaf issuer matches intermediate subject.":"Leaf issuer does not match intermediate subject.");const l=await k(e.leaf.cert,e.intermediate.keyPair.publicKey);b(r,"Leaf signature",l,l?"Leaf certificate signature verifies against intermediate key.":"Leaf signature is invalid.");const m=j(e.leaf.cert);b(r,"Leaf validity window",m,m?"Leaf certificate is within validity period.":"Leaf certificate is expired or not yet valid.");const p=await H(e.root.cert),y=t.trustedRoots.has(p);b(r,"Trust anchor check",y,y?"Root certificate exists in selected trust store.":"Root certificate is missing from trust store.");const h=I(e.leaf.cert,o)||I(e.intermediate.cert,o);b(r,"CRL revocation check",!h,h?"A certificate serial appears in a CRL.":"No certificate serial present in supplied CRLs.");const g=K(e.leaf.cert,n),v=K(e.intermediate.cert,n),E=g!=="revoked"&&v!=="revoked";return b(r,"OCSP revocation check",E,E?`OCSP statuses: leaf=${g}, intermediate=${v}.`:`OCSP revoked status detected: leaf=${g}, intermediate=${v}.`),{ok:r.every(B=>B.ok),steps:r}}function Z(e,t=[]){return{issuer:e,revokedSerialNumbers:new Set(t)}}function ee(e,t=[]){return{issuer:e,statusBySerial:new Map(t.map(o=>[o.serialNumber,o.status]))}}function I(e,t){for(const o of t)if(o.issuer===e.issuer&&o.revokedSerialNumbers.has(e.serialNumber))return!0;return!1}function K(e,t){for(const o of t)if(o.issuer===e.issuer)return o.statusBySerial.get(e.serialNumber)??"unknown";return"unknown"}function te(e,t){const o=new Set;return t?t==="root"?(o.add(e.root.cert.subject),o.add(e.intermediate.cert.subject),o.add(e.leaf.cert.subject),o):(o.add(e.intermediate.cert.subject),o.add(e.leaf.cert.subject),o):o}const V=document.querySelector("#app");if(!V)throw new Error("Missing app root element.");function $(e,t=12){return e.length>t*2?`${e.slice(0,t)}...${e.slice(-t)}`:e}function P(e){return e.replace("CN=","")}function re(e,t){return t==="root"?e.chain.root.cert:t==="intermediate"?e.chain.intermediate.cert:e.chain.leaf.cert}function N(e){return{...e,subject:`${e.subject} [tampered]`}}async function f(e){const t=e.revokeViaCrl?[Z(e.chain.leaf.cert.issuer,[e.chain.leaf.cert.serialNumber])]:[],o=e.revokeViaOcsp?[ee(e.chain.leaf.cert.issuer,[{serialNumber:e.chain.leaf.cert.serialNumber,status:"revoked"}])]:[];e.validation=await X(e.chain,e.trustStores[e.trustContext],t,o)}function oe(e){var a,c,d,s,l,m;const t=re(e,e.selectedNode),o=te(e.chain,e.compromisedCa),n=((a=e.validation)==null?void 0:a.ok)??!1,r=t.signature.byteLength,i={classical:{title:"Classical P-256 Chain",alg:"ECDSA P-256",sigBytes:"64-72 bytes",keyBytes:"65 bytes public key",note:"Current web PKI baseline with broad browser and HSM support."},mldsa:{title:"Post-Quantum ML-DSA Chain",alg:"ML-DSA (Dilithium family)",sigBytes:"~2,420 bytes",keyBytes:"~1,312 bytes public key",note:"Stronger against quantum adversaries but larger artifacts and ecosystem rollout risk."},hybrid:{title:"Hybrid Transition Chain",alg:"ECDSA + ML-DSA dual signatures",sigBytes:"Classical + PQ total",keyBytes:"Dual key material",note:"Preferred migration path: maintain compatibility while adding PQ assurance."}}[e.pqMode];return`
    <header class="hero panel">
      <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Toggle theme">
        ${e.theme==="dark"?"Light":"Dark"}
      </button>
      <p class="eyebrow">crypto-lab interactive exhibit</p>
      <h1>PKI Chain, Trust, and CT</h1>
      <p class="lede">Explore certificate chain trust, CA failure blast radius, and Certificate Transparency monitoring in one browser-native lab.</p>
    </header>

    <section class="panel exhibit" id="exhibit-1">
      <h2>Exhibit 1 - The Chain</h2>
      <p class="caption">Root CA -> Intermediate CA -> Leaf certificate with trust propagation from anchor to endpoint.</p>
      <div class="chain-row ${n?"trust-flow-on":""}">
        <button type="button" class="cert-chip ${e.selectedNode==="root"?"active":""} ${o.has(e.chain.root.cert.subject)?"compromised":""}" data-select="root">Root CA</button>
        <span class="arrow">-></span>
        <button type="button" class="cert-chip ${e.selectedNode==="intermediate"?"active":""} ${o.has(e.chain.intermediate.cert.subject)?"compromised":""}" data-select="intermediate">Intermediate</button>
        <span class="arrow">-></span>
        <button type="button" class="cert-chip ${e.selectedNode==="leaf"?"active":""} ${o.has(e.chain.leaf.cert.subject)?"compromised":""}" data-select="leaf">Leaf</button>
      </div>
      <div class="cert-inspector">
        <p><strong>Subject:</strong> ${t.subject}</p>
        <p><strong>Issuer:</strong> ${t.issuer}</p>
        <p><strong>Serial:</strong> <span class="mono">${t.serialNumber}</span></p>
        <p><strong>Validity:</strong> ${new Date(t.validFrom).toLocaleDateString()} - ${new Date(t.validTo).toLocaleDateString()}</p>
        <p><strong>Public Key Type:</strong> ${t.publicKey.kty??"unknown"} / ${t.publicKey.crv??t.publicKey.alg??"n/a"}</p>
        <p><strong>Signature Size:</strong> ${r} bytes</p>
      </div>
    </section>

    <section class="panel exhibit" id="exhibit-2">
      <h2>Exhibit 2 - Chain Validation</h2>
      <p class="caption">Real WebCrypto signature verification at every link, plus trust anchor and revocation checks.</p>
      <div class="control-row">
        <button id="run-validation" class="btn" type="button">Run Validation</button>
        <button class="btn ghost" data-tamper="root" type="button">Tamper Root</button>
        <button class="btn ghost" data-tamper="intermediate" type="button">Tamper Intermediate</button>
        <button class="btn ghost" data-tamper="leaf" type="button">Tamper Leaf</button>
      </div>
      <div class="control-row">
        <label><input id="toggle-crl" type="checkbox" ${e.revokeViaCrl?"checked":""} /> Simulate CRL revocation</label>
        <label><input id="toggle-ocsp" type="checkbox" ${e.revokeViaOcsp?"checked":""} /> Simulate OCSP revoked</label>
      </div>
      <ul class="step-list">
        ${(((c=e.validation)==null?void 0:c.steps)??[]).map(p=>`<li class="${p.ok?"pass":"fail"}"><strong>${p.label}:</strong> ${p.details}</li>`).join("")}
      </ul>
      <p class="status ${(d=e.validation)!=null&&d.ok?"pass":"fail"}">Overall: ${(s=e.validation)!=null&&s.ok?"PASS":"FAIL"}</p>
    </section>

    <section class="panel exhibit" id="exhibit-3">
      <h2>Exhibit 3 - Trust Stores</h2>
      <p class="caption">The same chain can be accepted or rejected depending on browser, OS, or app trust roots.</p>
      <div class="tab-row">
        <button class="tab ${e.trustContext==="browser"?"active":""}" data-context="browser" type="button">Browser Store</button>
        <button class="tab ${e.trustContext==="os"?"active":""}" data-context="os" type="button">OS Store</button>
        <button class="tab ${e.trustContext==="application"?"active":""}" data-context="application" type="button">Application Store</button>
      </div>
      <p>Current context: <strong>${e.trustContext}</strong></p>
      <p>Root fingerprint: <span class="mono">${$(e.rootFingerprint,18)}</span></p>
      <p>Context trust decision: <strong>${(l=e.validation)!=null&&l.ok?"Trusted":"Rejected"}</strong></p>
      <div class="incident-grid">
        <article><h3>DigiNotar (2011)</h3><p>Fraudulent certs for major domains triggered emergency root distrust.</p></article>
        <article><h3>Symantec Distrust (2017)</h3><p>Chrome removed trust after systemic issuance and audit failures.</p></article>
        <article><h3>TrustCor Removal (2022)</h3><p>Mozilla removed root trust over ownership and compliance concerns.</p></article>
      </div>
    </section>

    <section class="panel exhibit" id="exhibit-4">
      <h2>Exhibit 4 - CA Compromise</h2>
      <p class="caption">Mark a CA as compromised and observe cascading distrust across its issued subtree.</p>
      <div class="tab-row">
        <button class="tab ${e.compromisedCa===null?"active":""}" data-compromise="none" type="button">No Compromise</button>
        <button class="tab ${e.compromisedCa==="intermediate"?"active":""}" data-compromise="intermediate" type="button">Intermediate Compromised</button>
        <button class="tab ${e.compromisedCa==="root"?"active":""}" data-compromise="root" type="button">Root Compromised</button>
      </div>
      <p>Untrusted subtree:</p>
      <ul class="subtree-list">
        <li class="${o.has(e.chain.root.cert.subject)?"fail":"pass"}">${P(e.chain.root.cert.subject)}</li>
        <li class="${o.has(e.chain.intermediate.cert.subject)?"fail":"pass"}">${P(e.chain.intermediate.cert.subject)}</li>
        <li class="${o.has(e.chain.leaf.cert.subject)?"fail":"pass"}">${P(e.chain.leaf.cert.subject)}</li>
      </ul>
      <p class="incident-note"><strong>DigiNotar 2011:</strong> attacker-issued fraudulent certificates (including google.com), prompting browser vendors to distrust the CA and break trust for all descendants.</p>
    </section>

    <section class="panel exhibit" id="exhibit-5">
      <h2>Exhibit 5 - Certificate Transparency</h2>
      <p class="caption">Submit certificates to a simulated append-only log, mint SCTs, verify inclusion, and catch misissuance.</p>
      <div class="control-row">
        <button id="ct-submit" class="btn" type="button">Submit Leaf to CT Log</button>
        <button id="ct-proof" class="btn ghost" type="button" ${e.ctLog.size<1?"disabled":""}>Inclusion Proof</button>
        <button id="ct-consistency" class="btn ghost" type="button" ${e.ctLog.size<2?"disabled":""}>Consistency Proof</button>
        <button id="ct-misissue" class="btn danger" type="button">Simulate Misissuance</button>
      </div>
      <p>Log size: <strong>${e.ctLog.size}</strong> | Log ID: <span class="mono">${$(e.ctLog.logId,14)}</span></p>
      <p>SCT: ${e.latestSct?`<span class="mono">${$(e.latestSct.entryHash,14)}</span> at ${new Date(e.latestSct.timestamp).toLocaleTimeString()}`:"No SCT generated yet."}</p>
      <p>Inclusion proof: ${e.latestProof?`${e.latestProof.auditPath.length} sibling hashes, verify=${e.latestProofValid?"true":"false"}`:"Not generated."}</p>
      <p>Consistency proof: ${e.latestConsistency?`old=${e.latestConsistency.oldSize}, new=${e.latestConsistency.newSize}, verify=${e.latestConsistencyValid?"true":"false"}`:"Not generated."}</p>
      <p class="status ${(m=e.misissuance)!=null&&m.suspicious?"fail":"pass"}">Misissuance monitor: ${e.misissuance?e.misissuance.reason:"No suspicious issuance observed."}</p>
      <p class="incident-note">CT bridge: Merkle proofs from this panel mirror the trust model used by public browser CT logs.</p>
    </section>

    <section class="panel exhibit" id="exhibit-6">
      <h2>Exhibit 6 - PQ Migration</h2>
      <p class="caption">Compare classical and post-quantum certificate chain signatures and migration strategy.</p>
      <div class="tab-row">
        <button class="tab ${e.pqMode==="classical"?"active":""}" data-pq="classical" type="button">P-256</button>
        <button class="tab ${e.pqMode==="mldsa"?"active":""}" data-pq="mldsa" type="button">ML-DSA</button>
        <button class="tab ${e.pqMode==="hybrid"?"active":""}" data-pq="hybrid" type="button">Hybrid</button>
      </div>
      <h3>${i.title}</h3>
      <p><strong>Algorithm:</strong> ${i.alg}</p>
      <p><strong>Signature footprint:</strong> ${i.sigBytes}</p>
      <p><strong>Public key footprint:</strong> ${i.keyBytes}</p>
      <p>${i.note}</p>
      <p class="incident-note">Compatibility note: browsers currently validate classical WebPKI signatures; PQ rollouts are expected to use hybrid certificates first.</p>
    </section>

    <footer class="panel footer-note">
      <p>So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31</p>
    </footer>
  `}function ie(e){var o,n,r,i,a,c,d;const t=document.querySelector("#theme-toggle");t==null||t.addEventListener("click",()=>{e.theme=e.theme==="dark"?"light":"dark",document.documentElement.dataset.theme=e.theme,localStorage.setItem("crypto-lab-theme",e.theme),u(e)}),document.querySelectorAll("[data-select]").forEach(s=>{s.addEventListener("click",()=>{e.selectedNode=s.dataset.select,u(e)})}),(o=document.querySelector("#run-validation"))==null||o.addEventListener("click",async()=>{await f(e),u(e)}),document.querySelectorAll("[data-tamper]").forEach(s=>{s.addEventListener("click",async()=>{const l=s.dataset.tamper;l==="root"?e.chain.root.cert=N(e.chain.root.cert):l==="intermediate"?e.chain.intermediate.cert=N(e.chain.intermediate.cert):e.chain.leaf.cert=N(e.chain.leaf.cert),e.tamperedNodes.add(l),await f(e),u(e)})}),(n=document.querySelector("#toggle-crl"))==null||n.addEventListener("change",async s=>{const l=s.target;e.revokeViaCrl=l.checked,await f(e),u(e)}),(r=document.querySelector("#toggle-ocsp"))==null||r.addEventListener("change",async s=>{const l=s.target;e.revokeViaOcsp=l.checked,await f(e),u(e)}),document.querySelectorAll("[data-context]").forEach(s=>{s.addEventListener("click",async()=>{e.trustContext=s.dataset.context,await f(e),u(e)})}),document.querySelectorAll("[data-compromise]").forEach(s=>{s.addEventListener("click",()=>{const l=s.dataset.compromise;e.compromisedCa=l==="none"?null:l,u(e)})}),(i=document.querySelector("#ct-submit"))==null||i.addEventListener("click",async()=>{e.latestSct=await e.ctLog.submitCertificate(e.chain.leaf.cert),e.latestProof=null,e.latestConsistency=null,u(e)}),(a=document.querySelector("#ct-proof"))==null||a.addEventListener("click",async()=>{const s=e.ctLog.size-1;s<0||(e.latestProof=await e.ctLog.generateInclusionProof(s),e.latestProofValid=await e.ctLog.verifyInclusionProof(e.latestProof),u(e))}),(c=document.querySelector("#ct-consistency"))==null||c.addEventListener("click",async()=>{e.ctLog.size<2||(e.latestConsistency=await e.ctLog.generateConsistencyProof(e.ctLog.size-1,e.ctLog.size),e.latestConsistencyValid=await e.ctLog.verifyConsistencyProof(e.latestConsistency),u(e))}),(d=document.querySelector("#ct-misissue"))==null||d.addEventListener("click",async()=>{const s={...e.chain.leaf.cert,issuer:"CN=Compromised DigiNotar CA",serialNumber:`${e.chain.leaf.cert.serialNumber}ff`};await e.ctLog.submitCertificate(s),e.misissuance=e.ctLog.detectMisissuance(s,new Set([e.chain.intermediate.cert.subject])),u(e)}),document.querySelectorAll("[data-pq]").forEach(s=>{s.addEventListener("click",()=>{e.pqMode=s.dataset.pq,u(e)})})}function u(e){V.innerHTML=`<main class="page">${oe(e)}</main>`,ie(e)}async function ne(){const e=await J(),t=await Y(e.root.cert),o=await H(e.root.cert),n={trustedRoots:new Set},r={trustedRoots:new Set([o])},i=localStorage.getItem("crypto-lab-theme")??"dark";document.documentElement.dataset.theme=i;const a={chain:e,selectedNode:"leaf",validation:null,trustStores:{browser:t,os:n,application:r},trustContext:"browser",tamperedNodes:new Set,revokeViaCrl:!1,revokeViaOcsp:!1,compromisedCa:null,ctLog:await G(),latestSct:null,latestProof:null,latestProofValid:null,latestConsistency:null,latestConsistencyValid:null,misissuance:null,theme:i,pqMode:"classical",rootFingerprint:o};await f(a),u(a)}ne();
