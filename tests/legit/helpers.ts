import { test, expect, Page, APIRequestContext, APIResponse } from '@playwright/test';

// WAF responses carry "Server: awselb/2.0" (403 block, 500 fail-closed); backend errors do not.
const blocked: string[] = [];

function isWafBlock(status: number, server: string | undefined): boolean {
  return (status === 403 || status === 500) && (server || '').toLowerCase() === 'awselb/2.0';
}

export function wafGuard(page: Page) {
  page.on('response', (r) => {
    if (isWafBlock(r.status(), r.headers()['server'])) blocked.push(`${r.status()} ${r.request().method()} ${r.url()}`);
  });
}

export function checkApi(r: APIResponse, what: string) {
  if (isWafBlock(r.status(), r.headers()['server'])) blocked.push(`${r.status()} ${what} ${r.url()}`);
}

test.afterEach(async () => {
  const list = blocked.splice(0);
  expect(list, `WAF blocked:\n${list.join('\n')}`).toEqual([]);
});

// Odoo major version from the project name (shop12 → 12).
export function odooVersion(): number {
  return parseInt(test.info().project.name.replace(/\D/g, ''), 10);
}

export async function rpc(request: APIRequestContext, model: string, method: string, args: unknown[], kwargs: Record<string, unknown> = {}) {
  const r = await request.post(`/web/dataset/call_kw/${model}/${method}`, {
    data: { jsonrpc: '2.0', method: 'call', id: Date.now(), params: { model, method, args, kwargs } },
  });
  checkApi(r, `rpc ${model}.${method}`);
  expect(r.status(), `rpc ${model}.${method} HTTP status`).toBe(200);
  const body = await r.json();
  if (body.error) throw new Error(`rpc ${model}.${method}: ${JSON.stringify(body.error).slice(0, 500)}`);
  return body.result;
}

// The login form is scoped: with website installed, the page header has other submit buttons
// (Odoo 18: a hidden search button), and "/web/login" itself matches /\/(web|odoo)/.
export async function login(page: Page) {
  await page.goto('/web/login');
  const form = page.locator('form.oe_login_form');
  await form.locator('input[name=login]').fill('admin');
  await form.locator('input[name=password]').fill('admin');
  await form.locator('button[type=submit]').click();
  await page.waitForURL((u) => /^\/(web|odoo)/.test(u.pathname) && !u.pathname.startsWith('/web/login'));
}

// Backend views keep a long-polling (12/14) or bus connection open, so "networkidle" may never
// come: wait for the web client action instead (Odoo 12: .o_content; 14–18: children of .o_action_manager).
export async function waitBackendView(page: Page) {
  await page.waitForLoadState('load');
  await page.locator('.o_content, .o_action_manager > *').first().waitFor({ state: 'attached', timeout: 60_000 });
  await page.waitForTimeout(1000); // let the view issue its RPCs
}
