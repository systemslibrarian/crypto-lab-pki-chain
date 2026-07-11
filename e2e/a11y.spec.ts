import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the PKI/CT unit tests;
 * this gates them on accessibility the same way. The page renders all six
 * exhibits at once (no hidden tabs/details — the "tabs" swap state but every
 * section stays in the DOM), yet several exhibits inject dynamic result
 * regions only after you drive them. Before scanning we run every live demo so
 * those async regions exist, neutralize animations/transitions/opacity (a
 * mid-fade opacity produces phantom contrast failures), park the pointer so no
 * button sits in :hover, and scan in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content: `*,*::before,*::after{
      animation:none!important;
      transition:none!important;
      opacity:1!important;
      scroll-behavior:auto!important;
    }`,
  });
}

/** Open every <details> (defensive — none today) so nothing is collapsed. */
async function revealEverything(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
  });
}

/** Drive each interactive exhibit so dynamically-injected regions get scanned. */
async function driveDemos(page: Page): Promise<void> {
  // Exhibit 1 — inspect each chain node so every cert-inspector variant renders.
  await page.locator('[data-select="root"]').click();
  await page.locator('[data-select="intermediate"]').click();
  await page.locator('[data-select="leaf"]').click();

  // Exhibit 2 — run validation, then tamper the leaf so a FAIL status renders,
  // and toggle revocation so those step/status regions exist.
  await page.locator('#run-validation').click();
  await page.locator('[data-tamper="leaf"]').click();
  await page.locator('#toggle-crl').check();
  await page.locator('#toggle-ocsp').check();
  await expect(page.locator('.step-list li').first()).toBeVisible();

  // Exhibit 4 — compromise a CA so the failed subtree list renders.
  await page.locator('[data-compromise="intermediate"]').click();

  // Exhibit 5 — CT log: submit twice, then inclusion + consistency + misissuance.
  await page.locator('#ct-submit').click();
  await page.locator('#ct-submit').click();
  await page.locator('#ct-proof').click();
  await page.locator('#ct-consistency').click();
  await page.locator('#ct-misissue').click();
  await expect(page.locator('#exhibit-5 .status')).toBeVisible();

  // Exhibit 6 — cycle PQ modes so each detail/bar variant renders.
  await page.locator('[data-pq="mldsa"]').click();
  await page.locator('[data-pq="hybrid"]').click();
  await page.locator('[data-pq="classical"]').click();
}

async function scan(page: Page): Promise<void> {
  await revealEverything(page);
  await neutralizeMotion(page);
  await page.mouse.move(0, 0);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#exhibit-1')).toBeVisible();
  await driveDemos(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#exhibit-1')).toBeVisible();
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await driveDemos(page);
  await scan(page);
});
