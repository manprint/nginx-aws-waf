import { test } from '@playwright/test';
import { wafGuard, checkApi } from '../helpers';

test('website: pages, contact form, avatar', async ({ page }) => {
  wafGuard(page);
  for (const p of ['/', '/shop', '/contactus']) {
    await page.goto(p);
    await page.waitForLoadState('networkidle');
  }
  // Odoo 12/14 post the contact form to /website_form/, 16/18 to /website/form/
  const form = page.locator('form[action*="/website/form/"], form[action*="/website_form/"]').first();
  if (await form.count() > 0) {
    const fill = async (name: string, value: string) => {
      const f = form.locator(`[name="${name}"]`);
      if (await f.count() > 0 && await f.first().isVisible()) await f.first().fill(value);
    };
    await fill('name', 'Mario Rossi');
    await fill('contact_name', 'Mario Rossi');
    await fill('email_from', 'mario.rossi@example.org');
    await fill('phone', '+39 333 1234567');
    await fill('partner_name', 'Rossi Srl');
    await fill('subject', 'Richiesta informazioni');
    await fill('description', 'UNION of interests; please DROP me a line. See https://example.org for details.');
    const send = form.locator('.s_website_form_send, .o_website_form_send, button[type=submit]').first();
    await send.click();
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(1500);
  } else {
    test.info().annotations.push({ type: 'note', description: 'no contact form' });
  }
  const r = await page.request.get('/web/image/res.partner/1/avatar_128');
  checkApi(r, 'avatar');
});
