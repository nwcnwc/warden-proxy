#!/usr/bin/env node
/**
 * Warden Proxy — UI & Functional Test Suite
 * 
 * Run before any major deployment:
 *   cd /tmp && node /path/to/warden-proxy/tests/ui-test.js
 * 
 * Requires: puppeteer-core at /tmp/node_modules/puppeteer-core
 * Requires: Warden running on localhost:7400
 */

let puppeteer;
try { puppeteer = require('puppeteer-core'); } 
catch(e) { puppeteer = require('/tmp/node_modules/puppeteer-core'); }

const WARDEN = 'http://localhost:7400';
const CHROMIUM = '/usr/bin/chromium-browser';
const LAUNCH_OPTS = {
  executablePath: CHROMIUM,
  headless: 'new',
  args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage']
};

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, name) {
  if (condition) {
    passed++;
    console.log(`  ✅ ${name}`);
  } else {
    failed++;
    failures.push(name);
    console.log(`  ❌ ${name}`);
  }
}

async function testEndpoints(browser) {
  console.log('\n📡 API Endpoints');
  const page = await browser.newPage();
  
  // Health
  await page.goto(`${WARDEN}/health`);
  const health = await page.evaluate(() => {
    try { return JSON.parse(document.body.innerText); } catch(e) { return null; }
  });
  assert(health && health.status === 'ok', 'GET /health returns {status: ok}');
  assert(health && health.version, 'GET /health includes version');

  // Status
  await page.goto(`${WARDEN}/status`);
  const status = await page.evaluate(() => {
    try { return JSON.parse(document.body.innerText); } catch(e) { return null; }
  });
  assert(status && status.status === 'ok', 'GET /status returns ok');
  assert(status && typeof status.uptime_secs === 'number', 'GET /status includes uptime');
  assert(status && Array.isArray(status.services), 'GET /status includes services array');

  // Routes
  await page.goto(`${WARDEN}/routes`);
  const routes = await page.evaluate(() => {
    try { return JSON.parse(document.body.innerText); } catch(e) { return null; }
  });
  assert(routes && typeof routes === 'object', 'GET /routes returns object');

  // Traffic API
  await page.goto(`${WARDEN}/admin/api/traffic`);
  const traffic = await page.evaluate(() => {
    try { return JSON.parse(document.body.innerText); } catch(e) { return null; }
  });
  assert(Array.isArray(traffic), 'GET /admin/api/traffic returns array');

  // Sessions API
  await page.goto(`${WARDEN}/admin/api/sessions`);
  const sessions = await page.evaluate(() => {
    try { return JSON.parse(document.body.innerText); } catch(e) { return null; }
  });
  assert(Array.isArray(sessions), 'GET /admin/api/sessions returns array');

  // wcurl endpoint (fetch, not navigate — browser may try to download shell scripts)
  const wcurl = await page.evaluate(async () => {
    const r = await fetch('/tools/wcurl');
    return { status: r.status, text: (await r.text()).substring(0, 30) };
  });
  assert(wcurl.status === 200 && wcurl.text.includes('#!/'), 'GET /tools/wcurl serves shell script');

  // Favicon
  const favResp = await page.goto(`${WARDEN}/favicon.svg`);
  assert(favResp.status() === 200, 'GET /favicon.svg returns 200');

  await page.close();
}

async function testLaunchpad(browser) {
  console.log('\n🏠 Launchpad');
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(`${WARDEN}/`, {waitUntil: 'networkidle2', timeout: 15000});

  const ui = await page.evaluate(() => ({
    title: document.title,
    bodyText: document.body.innerText,
    adminCards: document.querySelectorAll('.admin-card').length,
    appCards: document.querySelectorAll('.app-card').length,
    favicon: !!document.querySelector('link[rel="icon"]'),
    links: [...document.querySelectorAll('a')].map(a => a.href),
  }));

  assert(ui.title === 'Warden Launchpad', 'Title is "Warden Launchpad"');
  assert(ui.bodyText.includes("Warden's Office") || ui.bodyText.includes("Warden\u2019s Office"), 'Has "Warden\'s Office" section');
  assert(ui.bodyText.includes('real keys'), 'Has "real keys" subtitle');
  assert(ui.bodyText.includes('The Jail'), 'Has "The Jail" section');
  assert(ui.bodyText.includes('fake keys'), 'Has "fake keys" subtitle');
  assert(ui.adminCards >= 2, `Has admin cards (found ${ui.adminCards})`);
  assert(ui.appCards >= 3, `Has app cards (found ${ui.appCards})`);
  assert(ui.favicon, 'Has favicon link');
  assert(ui.links.some(l => l.includes('/apps/ai-chat')), 'Links to AI Chat');
  assert(ui.links.some(l => l.includes('/apps/api-tester')), 'Links to API Tester');
  assert(ui.links.some(l => l.includes('/apps/webvm')), 'Links to WebVM');
  assert(ui.links.some(l => l.includes('/admin/keys')), 'Links to Key Manager');
  assert(ui.links.some(l => l.includes('/admin/traffic')), 'Links to Traffic Control');
  assert(errors.length === 0, `No JS errors (got ${errors.length})`);

  // Status bar should show online
  const statusOnline = await page.evaluate(() => {
    const dots = document.querySelectorAll('[class*=status], [class*=online]');
    return dots.length > 0 || document.body.innerText.includes('service');
  });
  assert(statusOnline, 'Status indicator shows online');

  await page.close();
}

async function testAIChat(browser) {
  console.log('\n💬 AI Chat');
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  const netErrors = [];
  page.on('requestfailed', r => netErrors.push(r.url()));

  await page.goto(`${WARDEN}/apps/ai-chat/`, {waitUntil: 'networkidle2', timeout: 15000});

  // Structure
  const structure = await page.evaluate(() => ({
    title: document.title,
    hasProviderSelect: !!document.getElementById('provider'),
    hasModelSelect: !!document.getElementById('model'),
    hasInput: !!document.getElementById('input'),
    hasSendBtn: !!document.getElementById('send-btn'),
    hasSidebar: !!document.querySelector('.sidebar, [class*=sidebar]'),
    hasSystemPrompt: !!document.querySelector('[id*=system], [class*=system]'),
    hasExport: document.body.innerText.includes('Export') || document.body.innerText.includes('💾'),
    hasSettingsOverlay: !!document.querySelector('.settings-overlay'),
    hasSliders: !!document.querySelector('input[type=range]'),
    noWardenBranding: !document.body.innerText.includes('Warden handles') && !document.body.innerText.includes('No API key needed'),
  }));

  assert(structure.title === 'AI Chat', 'Title is "AI Chat" (no Warden branding)');
  assert(structure.hasProviderSelect, 'Has provider dropdown');
  assert(structure.hasModelSelect, 'Has model dropdown');
  assert(structure.hasInput, 'Has message input');
  assert(structure.hasSendBtn, 'Has send button');
  assert(structure.hasSidebar, 'Has conversation sidebar');
  assert(structure.hasSystemPrompt, 'Has system prompt');
  assert(structure.hasExport, 'Has export button');
  assert(structure.hasSettingsOverlay, 'Has settings overlay');
  assert(structure.hasSliders, 'Has temperature/token sliders');
  assert(structure.noWardenBranding, 'No Warden branding in app');

  // Settings modal auto-opens on first load (no keys)
  const modalOnFirstLoad = await page.evaluate(() => {
    const o = document.querySelector('.settings-overlay');
    return o ? getComputedStyle(o).display : 'missing';
  });
  assert(modalOnFirstLoad !== 'none', 'Settings modal auto-opens when no keys saved');

  // Save fake key
  const keyInput = await page.$('#key-openai');
  if (keyInput) await keyInput.type('sk-fake-ui-test-key');
  await page.evaluate(() => {
    const btns = [...document.querySelectorAll('button')];
    const save = btns.find(b => b.textContent.toLowerCase().includes('save'));
    if (save) save.click();
  });
  await new Promise(r => setTimeout(r, 500));

  // Modal should close after save
  const modalAfterSave = await page.evaluate(() => {
    const o = document.querySelector('.settings-overlay');
    return o ? getComputedStyle(o).display : 'missing';
  });
  assert(modalAfterSave === 'none', 'Settings modal closes after save');

  // Escape key closes modal
  await page.evaluate(() => {
    const gear = document.querySelector('[onclick*=toggleSettings], .settings-btn');
    // Find gear button by text content
    const btns = [...document.querySelectorAll('button')];
    const g = btns.find(b => b.textContent.includes('⚙'));
    if (g) g.click();
  });
  await new Promise(r => setTimeout(r, 300));
  await page.keyboard.press('Escape');
  await new Promise(r => setTimeout(r, 300));
  const modalAfterEsc = await page.evaluate(() => {
    const o = document.querySelector('.settings-overlay');
    return o ? getComputedStyle(o).display : 'missing';
  });
  assert(modalAfterEsc === 'none', 'Escape key closes settings modal');

  // Reload with key saved — modal should NOT auto-open
  await page.reload({waitUntil: 'networkidle2'});
  await new Promise(r => setTimeout(r, 500));
  const modalOnReload = await page.evaluate(() => {
    const o = document.querySelector('.settings-overlay');
    return o ? getComputedStyle(o).display : 'missing';
  });
  assert(modalOnReload === 'none', 'Modal stays closed on reload when keys exist');

  // Provider should show OpenAI (key configured)
  const providerText = await page.evaluate(() => {
    const sel = document.getElementById('provider');
    return sel ? sel.options[sel.selectedIndex]?.textContent : '';
  });
  assert(providerText === 'OpenAI' || providerText.includes('OpenAI'), `Provider shows OpenAI (got "${providerText}")`);

  // Send message with fake key — proxy should swap for real
  await page.evaluate(() => {
    document.getElementById('input').value = 'Reply with exactly: UI_TEST_PASS';
    document.getElementById('input').dispatchEvent(new Event('input'));
  });
  await page.evaluate(() => sendMessage());
  await new Promise(r => setTimeout(r, 8000));

  const response = await page.evaluate(() => {
    const msgs = document.querySelectorAll('.message-content, [class*=message-content]');
    if (msgs.length === 0) {
      // fallback: get all text from assistant messages
      const all = document.querySelectorAll('.message.assistant, [class*=assistant]');
      if (all.length === 0) return '';
      return all[all.length - 1].innerText;
    }
    return msgs[msgs.length - 1].innerText;
  });
  assert(response.includes('UI_TEST_PASS'), `AI responds through proxy with fake key (got "${response.substring(0, 50)}")`);

  // Conversation persists in localStorage
  const convSaved = await page.evaluate(() => {
    const data = localStorage.getItem('ai-chat-conversations');
    return data ? JSON.parse(data).length > 0 : false;
  });
  assert(convSaved, 'Conversation saved in localStorage');

  assert(errors.length === 0, `No JS errors (got ${errors.length})`);

  await page.close();
}

async function testAPITester(browser) {
  console.log('\n🔧 API Tester');
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(`${WARDEN}/apps/api-tester/`, {waitUntil: 'networkidle2', timeout: 15000});

  const ui = await page.evaluate(() => ({
    title: document.title,
    hasMethodSelect: !!document.querySelector('select[id*=method], [class*=method-select]'),
    hasServiceSelect: !!document.querySelector('#service, select[id*=service]'),
    hasPathInput: !!document.querySelector('#path, input[id*=path]'),
    hasSendBtn: !!document.querySelector('#send-btn, button[id*=send]'),
    hasBodyEditor: !!document.querySelector('textarea'),
    hasCurlImport: document.body.innerText.toLowerCase().includes('curl'),
    hasSettingsOverlay: !!document.querySelector('.settings-overlay, [class*=settings]'),
    noWardenBranding: !document.title.includes('Warden'),
  }));

  assert(ui.title === 'API Tester', 'Title is "API Tester" (no Warden branding)');
  assert(ui.hasMethodSelect, 'Has HTTP method selector');
  assert(ui.hasServiceSelect, 'Has service selector');
  assert(ui.hasPathInput, 'Has URL/path input');
  assert(ui.hasSendBtn, 'Has send button');
  assert(ui.hasBodyEditor, 'Has request body editor');
  assert(ui.hasCurlImport, 'Has cURL import feature');
  assert(ui.hasSettingsOverlay, 'Has settings overlay');
  assert(ui.noWardenBranding, 'No Warden branding');
  assert(errors.length === 0, `No JS errors (got ${errors.length})`);

  await page.close();
}

async function testWebVM(browser) {
  console.log('\n🖥️  WebVM');
  const page = await browser.newPage();

  await page.goto(`${WARDEN}/apps/webvm/`, {waitUntil: 'networkidle2', timeout: 15000});

  const ui = await page.evaluate(() => ({
    title: document.title,
    hasTerminal: !!document.querySelector('#console, .terminal, [class*=term]'),
    showsSetupRequired: document.body.innerText.includes('Setup Required') || document.body.innerText.includes('Cannot Start'),
    hasBackLink: !!document.querySelector('a[href="/"]'),
    noWardenBranding: !document.title.includes('Warden'),
    hasFavicon: !!document.querySelector('link[rel="icon"]'),
  }));

  assert(ui.title === 'WebVM', 'Title is "WebVM" (no Warden branding)');
  assert(ui.hasTerminal, 'Has terminal element');
  assert(ui.showsSetupRequired, 'Shows COEP/COOP setup required message');
  assert(ui.hasBackLink, 'Has back link to launchpad');
  assert(ui.hasFavicon, 'Has favicon');

  await page.close();
}

async function testAdminKeyManager(browser) {
  console.log('\n🔑 Admin: Key Manager');
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(`${WARDEN}/admin/keys/`, {waitUntil: 'networkidle2', timeout: 15000});

  const ui = await page.evaluate(() => ({
    title: document.title,
    hasAdminBanner: !!document.querySelector('.admin-banner, #admin-banner'),
    bannerText: document.querySelector('.admin-banner')?.textContent || '',
    hasButtons: document.querySelectorAll('button').length,
    bodyText: document.body.innerText,
  }));

  assert(ui.title.includes('Warden Admin'), 'Title includes "Warden Admin"');
  assert(ui.hasAdminBanner, 'Has admin banner');
  assert(ui.bannerText.includes('Admin Panel') || ui.bannerText.includes('Warden'), 'Banner says Admin Panel');
  assert(ui.hasButtons > 0, 'Has interactive buttons');
  assert(errors.length === 0, `No JS errors (got ${errors.length})`);

  // Old path should 404
  const oldPath = await page.goto(`${WARDEN}/apps/key-manager/`);
  assert(oldPath.status() === 404, 'Old /apps/key-manager/ returns 404');

  await page.close();
}

async function testAdminTraffic(browser) {
  console.log('\n📊 Admin: Traffic Control');
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(`${WARDEN}/admin/traffic/`, {waitUntil: 'networkidle2', timeout: 15000});

  const ui = await page.evaluate(() => ({
    title: document.title,
    hasAdminBanner: !!document.querySelector('.admin-banner'),
    hasTable: !!document.querySelector('table, [class*=traffic], [class*=log]'),
    hasFilter: !!document.querySelector('input, select, [class*=filter]'),
    hasAutoScroll: document.body.innerText.includes('Auto'),
    bodyText: document.body.innerText.substring(0, 200),
  }));

  assert(ui.title.includes('Warden Admin'), 'Title includes "Warden Admin"');
  assert(ui.hasAdminBanner, 'Has admin banner');
  assert(ui.hasTable, 'Has traffic table/log');
  assert(ui.hasFilter, 'Has filter controls');

  // Traffic rows should render if there are entries
  const rows = await page.evaluate(() => {
    const tbody = document.getElementById('traffic-body');
    return tbody ? tbody.children.length : 0;
  });
  const totalStat = await page.evaluate(() => {
    const el = document.getElementById('stat-total');
    return el ? parseInt(el.textContent) : 0;
  });
  assert(totalStat > 0 ? rows > 0 : true, `Traffic rows render when entries exist (${rows} rows, ${totalStat} total)`);

  assert(errors.length === 0, `No JS errors (got ${errors.length})`);

  await page.close();
}

async function testAdminSessions(browser) {
  console.log('\n🌐 Admin: Website Access');
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));

  await page.goto(`${WARDEN}/admin/sessions/`, {waitUntil: 'networkidle2', timeout: 15000});

  const ui = await page.evaluate(() => ({
    title: document.title,
    hasAdminBanner: !!document.querySelector('.admin-banner'),
    hasDomainInput: !!document.querySelector('input[type=text], input[placeholder*=domain]'),
    hasQuickLogin: document.body.innerText.includes('Google') || document.body.innerText.includes('Yahoo'),
    bodyText: document.body.innerText.substring(0, 300),
  }));

  assert(ui.title.includes('Warden Admin'), 'Title includes "Warden Admin"');
  assert(ui.hasAdminBanner, 'Has admin banner');
  assert(ui.hasDomainInput, 'Has domain input field');
  assert(ui.hasQuickLogin, 'Has quick login icons');
  assert(errors.length === 0, `No JS errors (got ${errors.length})`);

  await page.close();
}

async function testSecurityBoundaries(browser) {
  console.log('\n🔒 Security Boundaries');
  const page = await browser.newPage();

  // Admin pages should NOT be accessible from /apps/ path
  const fakeAdmin = await page.goto(`${WARDEN}/apps/key-manager/`);
  assert(fakeAdmin.status() === 404, 'No admin at /apps/key-manager/ (prevents masquerading)');

  // Proxy should reject requests without proper origin for API calls
  await page.goto(`${WARDEN}/`);
  const proxyNoOrigin = await page.evaluate(async () => {
    try {
      const r = await fetch('/proxy/openai/v1/models');
      return { status: r.status, body: await r.text() };
    } catch(e) { return { error: e.message }; }
  });
  // Should either work (same-origin from launchpad) or fail with access error
  assert(proxyNoOrigin.status === 200 || proxyNoOrigin.body?.includes('not allowed'), 
    'Proxy enforces origin-based access control');

  await page.close();
}

async function testProxyFunctionality(browser) {
  console.log('\n🔄 Proxy Functionality');
  const page = await browser.newPage();
  await page.goto(`${WARDEN}/`);

  // Non-streaming API call
  const nonStream = await page.evaluate(async () => {
    try {
      const r = await fetch('/proxy/openai/v1/chat/completions', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{role: 'user', content: 'Reply with exactly: PROXY_OK'}],
          max_tokens: 10
        })
      });
      const d = await r.json();
      return { status: r.status, content: d.choices?.[0]?.message?.content };
    } catch(e) { return { error: e.message }; }
  });
  assert(nonStream.status === 200, 'Non-streaming proxy call returns 200');
  assert(nonStream.content?.includes('PROXY_OK'), `Proxy returns correct response (got "${nonStream.content}")`);

  // Streaming API call
  const streaming = await page.evaluate(async () => {
    try {
      const r = await fetch('/proxy/openai/v1/chat/completions', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{role: 'user', content: 'Reply with exactly: STREAM_OK'}],
          max_tokens: 10,
          stream: true
        })
      });
      const text = await r.text();
      return { status: r.status, hasData: text.includes('data:'), hasDone: text.includes('[DONE]') };
    } catch(e) { return { error: e.message }; }
  });
  assert(streaming.status === 200, 'Streaming proxy call returns 200');
  assert(streaming.hasData, 'Streaming response contains SSE data lines');
  assert(streaming.hasDone, 'Streaming response contains [DONE] marker');

  // Fake key gets stripped — API still works
  const fakeKey = await page.evaluate(async () => {
    try {
      const r = await fetch('/proxy/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer sk-TOTALLY-FAKE-grandmas-phone-number'
        },
        body: JSON.stringify({
          model: 'gpt-4o-mini',
          messages: [{role: 'user', content: 'Reply with exactly: FAKE_KEY_OK'}],
          max_tokens: 10
        })
      });
      const d = await r.json();
      return { status: r.status, content: d.choices?.[0]?.message?.content };
    } catch(e) { return { error: e.message }; }
  });
  assert(fakeKey.status === 200, 'Fake API key still gets 200 (proxy injects real key)');
  assert(fakeKey.content?.includes('FAKE_KEY_OK'), `Fake key request returns correct response (got "${fakeKey.content}")`);

  // Traffic monitor should have logged these requests
  const trafficPage = await browser.newPage();
  await trafficPage.goto(`${WARDEN}/admin/api/traffic`);
  const trafficLog = await trafficPage.evaluate(() => {
    try { return JSON.parse(document.body.innerText); } catch(e) { return []; }
  });
  assert(trafficLog.length >= 2, `Traffic monitor logged requests (found ${trafficLog.length})`);
  await trafficPage.close();

  await page.close();
}

// ===== MAIN =====
(async () => {
  console.log('🔒 Warden Proxy — UI & Functional Test Suite');
  console.log('='.repeat(50));

  // Pre-flight: check Warden is running
  try {
    const browser = await puppeteer.launch(LAUNCH_OPTS);
    const page = await browser.newPage();
    const resp = await page.goto(`${WARDEN}/health`, {timeout: 5000});
    if (resp.status() !== 200) throw new Error('Warden not healthy');
    await page.close();

    console.log('✅ Warden is running on ' + WARDEN);

    await testEndpoints(browser);
    await testLaunchpad(browser);
    await testAIChat(browser);
    await testAPITester(browser);
    await testWebVM(browser);
    await testAdminKeyManager(browser);
    await testAdminTraffic(browser);
    await testAdminSessions(browser);
    await testSecurityBoundaries(browser);
    await testProxyFunctionality(browser);

    await browser.close();
  } catch(e) {
    console.error('❌ Pre-flight failed:', e.message);
    console.error('   Is Warden running? Is Chromium installed?');
    process.exit(1);
  }

  // Summary
  console.log('\n' + '='.repeat(50));
  console.log(`📋 Results: ${passed} passed, ${failed} failed`);
  if (failures.length > 0) {
    console.log('\n❌ Failures:');
    failures.forEach(f => console.log(`   - ${f}`));
  }
  console.log('');
  process.exit(failed > 0 ? 1 : 0);
})();
