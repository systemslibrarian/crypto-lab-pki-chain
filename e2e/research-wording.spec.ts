import { expect, test } from '@playwright/test';
test('hybrid footprint explains AND, OR and mixed-chain scope', async ({ page }) => {
  await page.goto('.');
  await page.getByRole('tab', { name: 'Hybrid', exact: true }).click();
  const section = page.locator('#exhibit-6');
  await expect(section).toContainText('Requiring BOTH signatures (AND)');
  await expect(section).toContainText('same message, identity and keys');
  await expect(section).toContainText('AND rejects the forged object; OR accepts it');
  await expect(section).toContainText('PQ root alone does not protect classical lower links');
  await expect(section).toContainText('not a generated hybrid certificate');
});
