import { expect, test as base, type Page } from '@playwright/test';

/**
 * Functional claims gate.
 *
 * The a11y suite proves the six exhibits are reachable; this suite proves what
 * they assert is true. Everything here is anchored to a promise the README or
 * the page itself makes to a learner:
 *
 *  - the headline chain verdict is checked against the step results the page
 *    computed, never against a baked-in string, and its counts are required to
 *    add up (failed + passed == steps rendered);
 *  - every failure path — tamper at each of the three links, CRL revocation,
 *    OCSP revocation, an unknown trust anchor — must genuinely fail validation
 *    AND name which link or check broke;
 *  - the surfaces that describe one run must agree: Exhibit 1's sign/verify
 *    result, Exhibit 2's step list, Exhibit 2's overall verdict and Exhibit 4's
 *    per-link signature column all report the same chain;
 *  - the CT log's inclusion proof is required to be O(log n) and to make the
 *    recomputed root equal the stored root;
 *  - the PQ bars must be drawn to the scale they claim.
 *
 * Regressions pinned here (all three were live defects):
 *   1. "Reset lab" stayed disabled after CT submissions / PQ / node selection,
 *      so the log could never be emptied.
 *   2. Exhibit 4 read the pristine baseline, so it printed "signature verifies"
 *      for a link Exhibit 2 was reporting as failed.
 *   3. "Simulate Misissuance" grew the log without clearing the consistency
 *      readout, leaving "old=2 → new=3, verify=true" over a tree of size 4.
 */

/** Every test fails on an uncaught page exception or a console error. */
const test = base.extend<Record<string, never>>({
  page: async ({ page }, use) => {
    const problems: string[] = [];
    page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
    page.on('console', (m) => {
      if (m.type() === 'error') problems.push(`console.error: ${m.text()}`);
    });
    await use(page);
    expect(problems, 'page must raise no uncaught exceptions or console errors').toEqual([]);
  },
});

type Node = 'root' | 'intermediate' | 'leaf';

const SIG_STEP: Record<Node, string> = {
  root: 'Root self-signature',
  intermediate: 'Intermediate signature',
  leaf: 'Leaf signature',
};

async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('.step-list li').first()).toBeVisible();
}

/** The validation step list exactly as rendered. */
async function steps(page: Page): Promise<{ label: string; ok: boolean }[]> {
  return page.locator('.step-list li').evaluateAll((items) =>
    items.map((li) => ({
      label: (li.querySelector('strong')?.textContent ?? '').replace(/:$/, '').trim(),
      ok: li.classList.contains('pass'),
    })),
  );
}

async function overall(page: Page): Promise<string> {
  return ((await page.locator('#exhibit-2 .status').textContent()) ?? '').replace(/\s+/g, ' ').trim();
}

/**
 * The headline verdict must be derived from the steps beside it: PASS only when
 * every rendered step passed, FAIL naming exactly the ones that did not, with
 * counts that add up to the number of checks on screen.
 */
async function expectVerdictMatchesSteps(page: Page): Promise<{ label: string; ok: boolean }[]> {
  const rendered = await steps(page);
  expect(rendered.length, 'the validator must render its checks').toBeGreaterThan(0);
  const failed = rendered.filter((s) => !s.ok);
  const verdict = await overall(page);

  if (failed.length === 0) {
    expect(verdict).toBe(`Overall: PASS — all ${rendered.length} checks passed.`);
    await expect(page.locator('#exhibit-2 .status')).toHaveClass(/\bpass\b/);
  } else {
    // Parts must sum to the whole, and the verdict must name every broken check.
    expect(verdict).toBe(
      `Overall: FAIL — ${failed.length} of ${rendered.length} checks failed: ${failed
        .map((s) => s.label)
        .join(', ')}.`,
    );
    await expect(page.locator('#exhibit-2 .status')).toHaveClass(/\bfail\b/);
    expect(rendered.filter((s) => s.ok).length + failed.length).toBe(rendered.length);
  }
  return rendered;
}

/** Exhibit 4's per-link signature column, as rendered. */
async function compromiseTable(page: Page): Promise<{ link: string; sig: string; trust: string }[]> {
  return page.locator('.compromise-table tbody tr').evaluateAll((rows) =>
    rows.map((r) => {
      const cells = Array.from(r.querySelectorAll('th,td')).map((c) => (c.textContent ?? '').trim());
      return { link: cells[0], sig: cells[1], trust: cells[2] };
    }),
  );
}

/**
 * The cross-surface invariant: Exhibit 2's step list is the single source of
 * truth about signatures, and Exhibit 1's sign/verify badge plus Exhibit 4's
 * signature column must both agree with it for the currently selected link.
 */
async function expectSurfacesAgree(page: Page): Promise<void> {
  const rendered = await steps(page);
  const stepOk = (label: string): boolean => rendered.find((s) => s.label === label)?.ok ?? true;

  const table = await compromiseTable(page);
  const byLink: Record<string, Node> = {
    'Root CA': 'root',
    'Intermediate CA': 'intermediate',
    Leaf: 'leaf',
  };
  expect(table).toHaveLength(3);
  for (const row of table) {
    const node = byLink[row.link];
    expect(node, `unexpected link row: ${row.link}`).toBeTruthy();
    const expected = stepOk(SIG_STEP[node]) ? 'signature verifies' : 'signature fails';
    expect(
      row.sig,
      `Exhibit 4 must not contradict Exhibit 2 about the ${row.link} signature`,
    ).toContain(expected);
  }

  // Exhibit 1 shows the currently selected certificate's own verify result.
  const selected = (await page
    .locator('.cert-chip[aria-pressed="true"]')
    .getAttribute('data-select')) as Node;
  const badge = ((await page.locator('.sf-result').textContent()) ?? '').trim();
  expect(
    badge,
    `Exhibit 1 must not contradict Exhibit 2 about the ${selected} signature`,
  ).toContain(stepOk(SIG_STEP[selected]) ? 'valid' : 'invalid');

  // Exhibit 3's trust decision is the same overall verdict as Exhibit 2's.
  const ok = rendered.every((s) => s.ok);
  await expect(page.locator('#exhibit-3 .pass, #exhibit-3 .fail').last()).toHaveText(
    ok ? 'Trusted' : 'Rejected',
  );
}

// --- the good chain -----------------------------------------------------------

test('a well-formed chain passes every check, and the verdict says so by count', async ({
  page,
}) => {
  await open(page);
  const rendered = await expectVerdictMatchesSteps(page);
  expect(rendered.every((s) => s.ok), 'the demo chain must validate out of the box').toBe(true);

  // The checks the README promises are exercised must actually be present.
  const labels = rendered.map((s) => s.label);
  for (const required of [
    'Root self-signature',
    'Intermediate signature',
    'Leaf signature',
    'Trust anchor check',
    'CRL revocation check',
    'OCSP revocation check',
  ]) {
    expect(labels, `missing validation check: ${required}`).toContain(required);
  }
  await expect(page.locator('.chain-row')).toHaveClass(/trust-flow-on/);
  await expectSurfacesAgree(page);
});

// --- failure paths ------------------------------------------------------------

/**
 * Tampering a certificate's subject breaks that link's signature AND every
 * downstream check that reads the subject as a name: the child's issuer
 * linkage, and (for the root) the trust-anchor fingerprint, which is taken over
 * the same payload. Pinning the exact cascade documents RFC 5280 name chaining
 * rather than just asserting "something went red".
 */
const TAMPER_CASCADE: Record<Node, string[]> = {
  root: ['Root self-signature', 'Intermediate issuer linkage', 'Trust anchor check'],
  intermediate: ['Intermediate signature', 'Leaf issuer linkage'],
  leaf: ['Leaf signature'],
};

for (const node of ['root', 'intermediate', 'leaf'] as Node[]) {
  test(`tampering the ${node} certificate genuinely fails its signature, by name`, async ({
    page,
  }) => {
    await open(page);
    await page.locator(`[data-tamper="${node}"]`).click();

    const rendered = await expectVerdictMatchesSteps(page);
    // Not merely "labelled failed": the tampered link's own signature must be
    // among the failures, and the exact set of broken checks must be the
    // documented name-chaining cascade — no more, no fewer.
    const broken = rendered.filter((s) => !s.ok).map((s) => s.label);
    expect(broken).toContain(SIG_STEP[node]);
    expect(broken.slice().sort()).toEqual(TAMPER_CASCADE[node].slice().sort());
    // The sibling links' signed bytes are untouched, so their signatures hold.
    for (const other of (['root', 'intermediate', 'leaf'] as Node[]).filter((n) => n !== node)) {
      expect(
        rendered.find((s) => s.label === SIG_STEP[other])?.ok,
        `tampering ${node} must not break the ${other} signature`,
      ).toBe(true);
    }
    const verdict = await overall(page);
    for (const label of broken) {
      expect(verdict, 'the verdict must name every broken check').toContain(label);
    }
    await expect(page.locator(`#step-${node}`)).toHaveClass(/fail/);
    await expect(page.locator(`#step-${node}`)).toHaveClass(/flipped/);

    // The cause→effect panel must name the bytes and link to the broken check.
    const coupling = page.locator('.tamper-coupling');
    await expect(coupling).toBeVisible();
    await expect(coupling.locator('.tc-effect')).toHaveClass(/fail/);
    await expect(coupling.locator('.tc-effect')).toContainText('flipped to FAIL');
    await expect(coupling.locator('.tc-jump')).toHaveAttribute('href', `#step-${node}`);
    await expect(coupling.locator('.tc-jump')).toHaveText(SIG_STEP[node]);
    // The anchor it points at must exist.
    await expect(page.locator(`#step-${node}`)).toHaveCount(1);

    await expectSurfacesAgree(page);

    // Repair must genuinely restore it — a tamper the learner cannot undo would
    // make the exhibit a one-shot.
    await page.locator(`[data-tamper="${node}"]`).click();
    const repaired = await expectVerdictMatchesSteps(page);
    expect(repaired.every((s) => s.ok)).toBe(true);
    await expect(page.locator('.tamper-coupling')).toHaveCount(0);
  });
}

test('CRL revocation genuinely fails the chain and names the revocation check', async ({
  page,
}) => {
  await open(page);
  await page.locator('#toggle-crl').check();

  const rendered = await expectVerdictMatchesSteps(page);
  const broken = rendered.filter((s) => !s.ok).map((s) => s.label);
  expect(broken).toEqual(['CRL revocation check']);
  // Revocation must be a policy failure layered on top of good crypto — every
  // signature still verifies. That distinction is the whole point of the check.
  for (const node of ['root', 'intermediate', 'leaf'] as Node[]) {
    expect(rendered.find((s) => s.label === SIG_STEP[node])?.ok).toBe(true);
  }
  expect(await overall(page)).toContain('CRL revocation check');
  await expectSurfacesAgree(page);

  await page.locator('#toggle-crl').uncheck();
  expect((await expectVerdictMatchesSteps(page)).every((s) => s.ok)).toBe(true);
});

test('OCSP revocation genuinely fails the chain and names the revocation check', async ({
  page,
}) => {
  await open(page);
  await page.locator('#toggle-ocsp').check();

  const rendered = await expectVerdictMatchesSteps(page);
  expect(rendered.filter((s) => !s.ok).map((s) => s.label)).toEqual(['OCSP revocation check']);
  await expect(page.locator('.step-list li.fail')).toContainText('revoked');
  await expectSurfacesAgree(page);

  await page.locator('#toggle-ocsp').uncheck();
  expect((await expectVerdictMatchesSteps(page)).every((s) => s.ok)).toBe(true);
});

test('an unknown trust anchor rejects an otherwise perfect chain', async ({ page }) => {
  await open(page);
  await page.locator('[data-context="os"]').click();

  const rendered = await expectVerdictMatchesSteps(page);
  expect(rendered.filter((s) => !s.ok).map((s) => s.label)).toEqual(['Trust anchor check']);
  // The README's Exhibit 3 lesson: the math is fine, the policy is not.
  for (const node of ['root', 'intermediate', 'leaf'] as Node[]) {
    expect(rendered.find((s) => s.label === SIG_STEP[node])?.ok).toBe(true);
  }
  await expectSurfacesAgree(page);

  // The other two stores accept the same chain.
  for (const ctx of ['application', 'browser']) {
    await page.locator(`[data-context="${ctx}"]`).click();
    expect((await expectVerdictMatchesSteps(page)).every((s) => s.ok), ctx).toBe(true);
  }
});

test('revocation and tamper stack without either verdict swallowing the other', async ({
  page,
}) => {
  await open(page);
  await page.locator('[data-tamper="leaf"]').click();
  await page.locator('#toggle-crl').check();
  await page.locator('[data-context="os"]').click();

  const rendered = await expectVerdictMatchesSteps(page);
  const broken = rendered.filter((s) => !s.ok).map((s) => s.label).sort();
  expect(broken).toEqual(['CRL revocation check', 'Leaf signature', 'Trust anchor check'].sort());
  const verdict = await overall(page);
  for (const label of broken) {
    expect(verdict, 'the verdict must name every broken check, not just the first').toContain(label);
  }
  await expectSurfacesAgree(page);
});

// --- CA compromise ------------------------------------------------------------

test('CA compromise drops trust down the subtree while the signatures stay valid', async ({
  page,
}) => {
  await open(page);

  await page.locator('[data-compromise="intermediate"]').click();
  let table = await compromiseTable(page);
  expect(table.map((r) => r.trust.includes('distrusted'))).toEqual([false, true, true]);
  // Compromise must not touch the math.
  expect(table.every((r) => r.sig.includes('signature verifies'))).toBe(true);
  await expect(page.locator('.compromise-contrast')).toContainText('signature still verifies');
  await expectSurfacesAgree(page);

  await page.locator('[data-compromise="root"]').click();
  table = await compromiseTable(page);
  expect(table.map((r) => r.trust.includes('distrusted'))).toEqual([true, true, true]);
  expect(table.every((r) => r.sig.includes('signature verifies'))).toBe(true);

  await page.locator('[data-compromise="none"]').click();
  table = await compromiseTable(page);
  expect(table.every((r) => r.trust.includes('trusted'))).toBe(true);
});

test('regression: Exhibit 4 must not claim a tampered signature verifies', async ({ page }) => {
  // Exhibit 4 used to read the pristine baseline validation, so with a tamper
  // also applied it printed "signature verifies" — and its prose asserted
  // "every signature still verifies" — for the very link Exhibit 2 was
  // simultaneously reporting as FAILED.
  await open(page);
  await page.locator('[data-tamper="leaf"]').click();
  await page.locator('[data-compromise="intermediate"]').click();

  const rendered = await steps(page);
  expect(rendered.find((s) => s.label === 'Leaf signature')?.ok).toBe(false);

  const table = await compromiseTable(page);
  const leafRow = table.find((r) => r.link === 'Leaf')!;
  expect(leafRow.sig, 'Exhibit 4 must report the leaf signature as failing').toContain(
    'signature fails',
  );
  expect(leafRow.trust).toContain('distrusted');
  // ...and the prose must not assert the opposite of the table above it.
  const contrast = (await page.locator('.compromise-contrast').textContent()) ?? '';
  expect(contrast).not.toContain('every signature still verifies');
  expect(contrast).toContain('Both failure modes');

  await expectSurfacesAgree(page);
});

/**
 * Tamper and compromise are independent toggles, so Exhibit 4 has four states to
 * be honest about, not two. Each one is checked against the table it sits under
 * — the prose may never assert something the rows contradict.
 */
test('Exhibit 4 reads honestly in all four tamper x compromise states', async ({ page }) => {
  await open(page);
  const contrast = page.locator('.compromise-contrast');
  const tamper = page.locator('[data-tamper="leaf"]');

  /**
   * Whatever the prose says, it must match the rows: it may only claim every
   * signature verifies when every row says so, and may only claim a signature
   * fails when some row says so.
   */
  const expectProseMatchesTable = async (): Promise<void> => {
    const rows = await compromiseTable(page);
    const allVerify = rows.every((r) => r.sig.includes('signature verifies'));
    const text = (await contrast.textContent()) ?? '';
    if (allVerify) {
      expect(text, 'prose must not claim a failure the table does not show').not.toMatch(
        /signature\s+fails/,
      );
    } else {
      expect(text, 'prose must not claim every signature verifies over a failing row').not.toMatch(
        /every\s+signature\s+still\s+verifies/,
      );
    }
    await expectSurfacesAgree(page);
  };

  // 1. no tamper, no compromise — the invitation to try both.
  expect((await compromiseTable(page)).every((r) => r.sig.includes('signature verifies'))).toBe(
    true,
  );
  await expect(contrast).toContainText('all signatures verify and all links are trusted');
  await expect(contrast).not.toHaveClass(/is-compromise/);
  await expectProseMatchesTable();

  // 2. tamper only — the math breaks, policy does not.
  await tamper.click();
  let rows = await compromiseTable(page);
  expect(rows.find((r) => r.link === 'Leaf')!.sig).toContain('signature fails');
  expect(rows.every((r) => r.trust.includes('trusted') && !r.trust.includes('distrusted'))).toBe(
    true,
  );
  await expect(contrast).toContainText('No CA is compromised');
  await expect(contrast).toContainText('signature fails');
  await expectProseMatchesTable();

  // 3. tamper AND compromise — both failure modes, named separately.
  await page.locator('[data-compromise="intermediate"]').click();
  rows = await compromiseTable(page);
  expect(rows.find((r) => r.link === 'Leaf')!.sig).toContain('signature fails');
  expect(rows.map((r) => r.trust.includes('distrusted'))).toEqual([false, true, true]);
  await expect(contrast).toContainText('Both failure modes are running at once');
  await expectProseMatchesTable();

  // 4. compromise only — trust drops, every signature holds.
  await tamper.click();
  rows = await compromiseTable(page);
  expect(rows.every((r) => r.sig.includes('signature verifies'))).toBe(true);
  expect(rows.map((r) => r.trust.includes('distrusted'))).toEqual([false, true, true]);
  await expect(contrast).toContainText('every signature still verifies');
  await expect(contrast).toHaveClass(/is-compromise/);
  await expectProseMatchesTable();
});

/**
 * The strongest form of the invariant: across every combination of tamper site
 * and compromised CA, no link may ever read "signature verifies" in Exhibit 4
 * while Exhibit 2 reports its signature check failed. This is the contradiction
 * the fix exists to prevent, checked exhaustively rather than in one sample.
 */
test('regression: no tamper x compromise combination lets the panels contradict', async ({
  page,
}) => {
  await open(page);
  for (const node of ['root', 'intermediate', 'leaf'] as Node[]) {
    for (const ca of ['none', 'root', 'intermediate']) {
      await page.locator(`[data-tamper="${node}"]`).click();
      await page.locator(`[data-compromise="${ca}"]`).click();

      const rendered = await steps(page);
      expect(
        rendered.find((s) => s.label === SIG_STEP[node])?.ok,
        `${node} tampered: Exhibit 2 must report its signature failing`,
      ).toBe(false);

      const table = await compromiseTable(page);
      const row = table.find(
        (r) => r.link === { root: 'Root CA', intermediate: 'Intermediate CA', leaf: 'Leaf' }[node],
      )!;
      expect(
        row.sig,
        `tamper=${node} compromise=${ca}: Exhibit 4 contradicted Exhibit 2`,
      ).toContain('signature fails');
      await expectSurfacesAgree(page);

      await page.locator(`[data-tamper="${node}"]`).click();
    }
  }
  await page.locator('[data-compromise="none"]').click();
  expect((await expectVerdictMatchesSteps(page)).every((s) => s.ok)).toBe(true);
});

// --- Reset --------------------------------------------------------------------

test('regression: Reset lab is reachable after any change, and restores everything', async ({
  page,
}) => {
  // "Reset lab" used to watch only the tamper / revocation / compromise /
  // trust-store knobs, so a learner who had only submitted certificates to the
  // CT log was left with a permanently disabled button and no way to empty it.
  await open(page);
  const reset = page.locator('#reset-lab');
  await expect(reset, 'nothing has changed yet').toBeDisabled();

  await page.locator('#ct-submit').click();
  await expect(reset, 'a CT submission is a change Reset undoes').toBeEnabled();
  await reset.click();
  await expect(page.locator('#exhibit-5')).toContainText('Log size: 0');
  await expect(reset).toBeDisabled();

  await page.locator('[data-pq="hybrid"]').click();
  await expect(reset, 'the PQ selection is a change Reset undoes').toBeEnabled();
  await reset.click();
  await expect(page.locator('[data-pq="classical"]')).toHaveAttribute('aria-selected', 'true');

  await page.locator('[data-select="root"]').click();
  await expect(reset, 'the selected link is a change Reset undoes').toBeEnabled();
  await reset.click();
  await expect(page.locator('.cert-chip[data-select="leaf"]')).toHaveAttribute(
    'aria-pressed',
    'true',
  );

  // The full-house case: everything at once, then one click back to defaults.
  await page.locator('[data-tamper="leaf"]').click();
  await page.locator('#toggle-crl').check();
  await page.locator('#toggle-ocsp').check();
  await page.locator('[data-compromise="root"]').click();
  await page.locator('[data-context="os"]').click();
  await page.locator('#ct-submit').click();
  await page.locator('#ct-misissue').click();
  await expect(reset).toBeEnabled();

  await reset.click();
  expect((await expectVerdictMatchesSteps(page)).every((s) => s.ok)).toBe(true);
  await expect(page.locator('#exhibit-5')).toContainText('Log size: 0');
  await expect(page.locator('#toggle-crl')).not.toBeChecked();
  await expect(page.locator('#toggle-ocsp')).not.toBeChecked();
  await expect(page.locator('[data-compromise="none"]')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('[data-context="browser"]')).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('#exhibit-5 .status')).toContainText('No suspicious issuance observed');
  await expect(reset).toBeDisabled();
});

// --- Certificate Transparency -------------------------------------------------

test('inclusion proofs are O(log n) and rebuild exactly the stored root', async ({ page }) => {
  await open(page);
  for (let i = 0; i < 4; i++) await page.locator('#ct-submit').click();
  await expect(page.locator('#exhibit-5')).toContainText('Log size: 4');

  const leaves = page.locator('.mtree-node.leaf');
  await expect(leaves).toHaveCount(4);

  for (let i = 0; i < 4; i++) {
    await leaves.nth(i).click();

    // Exactly one target, and the audit path is log2(n) siblings — the README's
    // "lights up exactly the log₂(n) audit-path sibling hashes".
    await expect(page.locator('.mtree-node.is-target')).toHaveCount(1);
    await expect(page.locator('.mtree-node.is-target')).toHaveAttribute('aria-pressed', 'true');
    const siblings = await page.locator('.mtree-node.is-sibling').count();
    expect(siblings, `leaf ${i}: audit path must be log2(4) = 2 siblings`).toBe(2);

    // The legend's count must be the number of siblings actually highlighted.
    await expect(page.locator('.mtree-legend li').nth(1)).toContainText(`(${siblings} total)`);

    // "verify = true" must literally mean these two hashes match.
    const hashes = await page.locator('.root-line .root-hash').allTextContents();
    expect(hashes).toHaveLength(2);
    expect(hashes[0], 'recomputed root must equal the stored root').toBe(hashes[1]);
    await expect(page.locator('.root-eq')).toHaveText('=');
    await expect(page.locator('.root-verdict')).toHaveClass(/pass/);
    await expect(page.locator('.root-verdict')).toContainText(
      `the ${siblings} sibling hashes reconstruct exactly the log’s root`,
    );
    await expect(page.locator('.root-verdict')).toContainText(`leaf ${i} is provably in the log`);
  }

  // The proof must be a proof, not a redraw of the whole log: nodes off the path
  // are dimmed and stay secret.
  expect(await page.locator('.mtree-node.is-dim').count()).toBeGreaterThan(0);
});

test('consistency proofs verify, and misissuance retires them', async ({ page }) => {
  await open(page);
  for (let i = 0; i < 3; i++) await page.locator('#ct-submit').click();
  await page.locator('#ct-consistency').click();

  const line = page.getByText(/^Consistency proof:/);
  await expect(line).toContainText('old=2 → new=3');
  await expect(line).toContainText('verify=true');
  await expect(line.locator('.pass')).toHaveText('true');

  // Regression: "Simulate Misissuance" appends to the same log, so it must
  // invalidate the outstanding proofs exactly as a normal submission does. It
  // used to leave "old=2 → new=3, verify=true" standing over a tree of size 4.
  await page.locator('#ct-misissue').click();
  await expect(page.locator('#exhibit-5')).toContainText('Log size: 4');
  await expect(line).toHaveText('Consistency proof: Not generated.');
  await expect(page.locator('.root-compare')).toHaveCount(0);

  // And the misissuance monitor must name the rogue issuer, not just flag it.
  const monitor = page.locator('#exhibit-5 .status');
  await expect(monitor).toHaveClass(/fail/);
  await expect(monitor).toContainText('CN=Compromised DigiNotar CA');
});

test('CT controls unlock as the log grows rather than staying dead', async ({ page }) => {
  await open(page);
  await expect(page.locator('#ct-proof')).toBeDisabled();
  await expect(page.locator('#ct-consistency')).toBeDisabled();

  await page.locator('#ct-submit').click();
  await expect(page.locator('#ct-proof')).toBeEnabled();
  await expect(page.locator('#ct-consistency')).toBeDisabled();

  await page.locator('#ct-submit').click();
  await expect(page.locator('#ct-consistency')).toBeEnabled();

  // ...and they go back to disabled after a reset empties the log.
  await page.locator('#reset-lab').click();
  await expect(page.locator('#ct-proof')).toBeDisabled();
  await expect(page.locator('#ct-consistency')).toBeDisabled();
});

// --- PQ migration -------------------------------------------------------------

test('the PQ bars are drawn to the scale they claim, from the live signature', async ({ page }) => {
  await open(page);

  const rows = await page.locator('.pq-bar-row').evaluateAll((items) =>
    items.map((r) => ({
      label: (r.querySelector('.pq-bar-label')?.textContent ?? '').trim(),
      bytes: Number(
        (r.querySelector('.pq-bar-value')?.textContent ?? '').replace(/[^\d]/g, ''),
      ),
      width: Number(
        ((r.querySelector('.pq-bar-fill') as HTMLElement | null)?.style.width ?? '0').replace(
          '%',
          '',
        ),
      ),
    })),
  );
  expect(rows).toHaveLength(3);

  // The classical bar is tagged "measured", so it must equal the signature size
  // Exhibit 1 reports for the live chain.
  expect(rows[0].label).toContain('measured');
  const sigText = (await page.locator('#exhibit-1 .cert-fields dd').last().textContent()) ?? '';
  expect(rows[0].bytes, 'the measured bar must be the live signature size').toBe(
    Number(sigText.replace(/[^\d]/g, '')),
  );

  // Hybrid carries both signatures — parts must sum to the whole.
  expect(rows[2].bytes, 'the hybrid bar must be classical + ML-DSA').toBe(
    rows[0].bytes + rows[1].bytes,
  );

  // "drawn to scale": each width is its share of the largest bar.
  const max = Math.max(...rows.map((r) => r.bytes));
  for (const row of rows) {
    expect(Math.abs(row.width - Math.max(2, Math.round((row.bytes / max) * 100))), row.label).toBe(
      0,
    );
  }
  expect(rows[2].width, 'the largest footprint must be the full-width bar').toBe(100);

  // Switching mode must move the active detail block with it.
  await page.locator('[data-pq="mldsa"]').click();
  await expect(page.locator('#exhibit-6 h3')).toHaveText('ML-DSA-44');
  await expect(page.locator('#exhibit-6')).toContainText('FIPS 204 reference');
  await page.locator('[data-pq="classical"]').click();
  await expect(page.locator('#exhibit-6 h3')).toHaveText('ECDSA P-256');
  await expect(page.locator('#exhibit-6')).toContainText('measured live');
});

// --- the [hidden] override trap ----------------------------------------------

test('no element carrying the hidden attribute is actually rendered', async ({ page }) => {
  await open(page);
  await page.locator('[data-tamper="leaf"]').click();
  await page.locator('#ct-submit').click();
  await page.locator('#ct-proof').click();

  const leaks = await page.evaluate(() => {
    const out: { tag: string; cls: string; display: string }[] = [];
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      const cs = getComputedStyle(el as HTMLElement);
      if (cs.display !== 'none') {
        out.push({
          tag: (el as HTMLElement).tagName.toLowerCase(),
          cls: (el as HTMLElement).className?.toString().slice(0, 60) ?? '',
          display: cs.display,
        });
      }
    }
    return out;
  });
  expect(leaks, `elements marked hidden that still render: ${JSON.stringify(leaks)}`).toEqual([]);
});
