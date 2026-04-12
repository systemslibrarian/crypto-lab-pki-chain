import './style.css';
import { createDemoChain } from './pki';
import { createCtLog } from './ct';

const app = document.querySelector<HTMLDivElement>('#app');

if (!app) {
  throw new Error('Missing app root element.');
}

async function init(): Promise<void> {
  const chain = await createDemoChain();
  const ct = createCtLog();

  app.innerHTML = `
    <main class="page">
      <header class="hero">
        <p class="eyebrow">crypto-lab</p>
        <h1>PKI Chain</h1>
        <p class="lede">Interactive PKI and Certificate Transparency demo.</p>
      </header>
      <section class="card">
        <h2>Scaffold Ready</h2>
        <p>Chain subject: <span class="mono">${chain.leaf.subject}</span></p>
        <p>CT entries: <span class="mono">${ct.size}</span></p>
      </section>
    </main>
  `;
}

void init();