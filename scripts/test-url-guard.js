// Tests for Lefty's Malicious Site & URL Guard

const assert = require('assert');
const urlGuard = require('../src/url-guard');

async function run() {
  console.log('Running URL Guard tests...\n');

  // 1. URL detection
  assert.strictEqual(urlGuard.isUrl('https://example.com'), true);
  assert.strictEqual(urlGuard.isUrl('http://test.org/path?q=1'), true);
  assert.strictEqual(urlGuard.isUrl('github.com'), true);
  assert.strictEqual(urlGuard.isUrl('not a url'), false);
  assert.strictEqual(urlGuard.isUrl(''), false);
  console.log('ok   isUrl detection passed');

  // 2. Dangerous schemes
  assert.strictEqual(urlGuard.isDangerousScheme('javascript:alert(1)'), true);
  assert.strictEqual(urlGuard.isDangerousScheme('data:text/html,<script>evil()</script>'), true);
  assert.strictEqual(urlGuard.isDangerousScheme('vbscript:msgbox(1)'), true);
  assert.strictEqual(urlGuard.isDangerousScheme('file:///C:/Windows/System32/cmd.exe'), true);
  assert.strictEqual(urlGuard.isDangerousScheme('https://safe.example.com'), false);
  console.log('ok   dangerous scheme blocking passed');

  // 3. Domain extraction
  assert.strictEqual(urlGuard.extractDomain('https://sub.domain.co.uk/path'), 'sub.domain.co.uk');
  assert.strictEqual(urlGuard.extractDomain('google.com'), 'google.com');
  console.log('ok   domain extraction passed');

  // 4. Scheme check via checkUrl
  const schemeRes = await urlGuard.checkUrl('javascript:doBadThings()');
  assert.strictEqual(schemeRes.safe, false);
  assert.strictEqual(schemeRes.risk, 'high');
  console.log('ok   checkUrl blocks dangerous javascript: scheme');

  // 5. Punycode spoofing check
  const punyRes = await urlGuard.checkUrl('https://xn--paypl-qqa.com');
  assert.strictEqual(punyRes.safe, false);
  assert.strictEqual(punyRes.risk, 'high');
  console.log('ok   checkUrl blocks deceptive Punycode domain');

  // 6. Safe domain resolution
  const safeRes = await urlGuard.checkUrl('https://google.com');
  assert.strictEqual(safeRes.safe, true);
  console.log('ok   checkUrl verifies legitimate domain');

  // 7. Cloudflare test malware domain
  const malwareRes = await urlGuard.checkUrl('http://malware.testcategory.com');
  assert.strictEqual(malwareRes.safe, false);
  assert.strictEqual(malwareRes.provider, 'cloudflare-doh');
  console.log('ok   checkUrl blocks confirmed malware domain via Cloudflare DoH');

  console.log('\nAll URL Guard checks passed.');
}

run().catch((err) => {
  console.error('URL Guard test failed:', err);
  process.exit(1);
});
