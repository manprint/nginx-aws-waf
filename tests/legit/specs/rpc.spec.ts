import { test, expect } from '@playwright/test';
import { randomBytes } from 'crypto';
import { wafGuard, login, rpc } from '../helpers';

test('rpc: large HTML, search, attachment, chatter', async ({ page }) => {
  wafGuard(page);
  await login(page);
  const req = page.request; // shares the session cookie
  const chunk = '<p>Nota <b>cliente</b> <a href="https://example.com/x">link</a></p>';
  const html = chunk.repeat(Math.ceil(40 * 1024 / chunk.length));
  const id = await rpc(req, 'res.partner', 'create', [{ name: 'WAF legit partner', comment: html }]);
  expect(typeof id === 'number' || Array.isArray(id)).toBeTruthy();
  const pid: number = Array.isArray(id) ? id[0] : id;
  await rpc(req, 'res.partner', 'write', [[pid], { comment: html + '<p>aggiornato</p>' }]);
  await rpc(req, 'res.partner', 'search_read', [[['name', 'ilike', 'select']]], { fields: ['name'], limit: 5 });
  await rpc(req, 'ir.attachment', 'create', [{
    name: 'waf-legit.bin', datas: randomBytes(200 * 1024).toString('base64'),
    res_model: 'res.partner', res_id: pid,
  }]);
  await rpc(req, 'res.partner', 'message_post', [[pid]], { body: '<p>ciao <script>x</script>?</p>', message_type: 'comment' });
});
