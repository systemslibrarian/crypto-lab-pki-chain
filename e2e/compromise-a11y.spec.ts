import { test, expect } from '@playwright/test';
import { scan } from './gate';

test('compromise result states remain accessible at narrow width', async ({ page }) => {
  test.setTimeout(120000);
  await page.setViewportSize({ width: 380, height: 800 });
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('.');
  const lab = page.locator('#sibling-lab');
  for (const mode of ['constrained', 'unconstrained']) {
    await lab.locator('select').selectOption(mode);
    await lab.locator('#sibling-run').click();
    await expect(lab.locator('#sibling-run')).toBeEnabled();
    await expect(lab).not.toContainText('failed to run');
    await scan(page, 'compromise ' + mode);
  }
});
