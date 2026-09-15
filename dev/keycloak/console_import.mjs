import { chromium } from 'playwright';
import fs from 'fs';
const [,, fixture, resultFile] = process.argv;
const record = {};
const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage();
try {
  await page.goto('http://localhost:18180/admin/master/console/#/samlscope/clients', { waitUntil: 'networkidle', timeout: 60000 });
  if (await page.locator('#username').count()) {
    await page.fill('#username', 'admin');
    await page.fill('#password', 'admin');
    await page.click('#kc-login');
    await page.waitForTimeout(6000);
  }
  await page.getByText('Import client', { exact: true }).click();
  await page.waitForTimeout(2000);
  const fileInput = page.locator('input[type=file]');
  await fileInput.setInputFiles(fixture);
  record.file_uploaded = true;
  await page.waitForTimeout(4000);
  const save = page.getByRole('button', { name: /^save$/i });
  record.save_visible = await save.count();
  if (record.save_visible) { await save.first().click(); record.saved = true; }
  await page.waitForTimeout(5000);
  record.final_url = page.url();
  record.dialog_closed = (await page.getByText('Import client', { exact: true }).count()) > 0;
  record.body_text = (await page.locator('body').innerText()).slice(0, 1500);
  await page.screenshot({ path: 'import-result.png', fullPage: true });
} catch (error) {
  record.error = String(error).slice(0, 600);
  try { await page.screenshot({ path: 'failure.png', fullPage: true }); } catch {}
} finally {
  await browser.close();
}
fs.writeFileSync(resultFile, JSON.stringify(record, null, 2));
console.log(JSON.stringify(record, null, 2).slice(0, 1400));
