import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`validation and compromise panels fit ${width}px without clipping`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    await expect(page.locator('.step-list li').first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    const table = page.locator('.compromise-table');
    await table.scrollIntoViewIfNeeded();
    await expect(table).toContainText('Cryptographic signature');
    const scroll = page.locator('.compromise-table-wrap');
    await scroll.focus();
    await expect(scroll).toBeFocused();
    await scroll.press('ArrowRight');
    expect(await scroll.evaluate(e => getComputedStyle(e).overflowX)).toBe('auto');
    await page.locator('[data-tamper="intermediate"]').click();
    await expect(page.locator('#exhibit-2 .status.fail')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
