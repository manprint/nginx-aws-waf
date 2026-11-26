import { test } from '@playwright/test';
import { wafGuard, login, odooVersion, waitBackendView } from '../helpers';

test('backend: contacts, CRM pipeline, logout', async ({ page }) => {
  wafGuard(page);
  await login(page);
  const v = odooVersion();
  await page.goto(v >= 18 ? '/odoo/contacts' : '/web#action=contacts.action_contacts');
  await waitBackendView(page);
  // Odoo 18 ignores legacy /web# URLs and opens Discuss: use its /odoo/<app> route
  await page.goto(v >= 18 ? '/odoo/crm' : '/web#model=crm.lead&view_type=kanban');
  await waitBackendView(page);
  await page.goto('/web/session/logout');
  await page.waitForLoadState('load');
});
