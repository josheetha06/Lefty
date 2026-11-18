// Lefty's Malicious Site & URL Guard
// Protects against phishing, malware domains, drive-by downloads, and dangerous URI schemes.
// Uses Cloudflare Security DoH (1.1.1.2) for zero-latency, keyless malware filtering,
// and supports Google Safe Browsing API v4 when an API key is provided.

const DANGEROUS_SCHEMES = new Set([
  'javascript:', 'data:', 'vbscript:', 'file:', 'ms-msdt:', 'search-ms:', 'shell:', 'disk:'
]);

// Suspicious top-level indicators and deceptive patterns
const DECEPTIVE_TLDS = new Set(['.zip', '.mov']); // when used in URLs mimicking files
const PUNYCODE_PREFIX = 'xn--';

// In-memory cache for domain reputation (TTL 10 minutes)
const reputationCache = new Map();
const CACHE_TTL_MS = 10 * 60 * 1000;

function cleanDomain(domain) {
  return String(domain || '').trim().toLowerCase().replace(/\.+$/, '');
}

function extractUrl(text) {
  if (!text) return null;
  const match = String(text).match(/\b(https?:\/\/[^\s<>"'{}|\\^`]+|[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+(?:\/[^\s<>"'{}|\\^`]*)?)/i);
  return match ? match[0] : null;
}

function isUrl(text) {
  if (!text) return false;
  const trimmed = String(text).trim();
  if (/^https?:\/\//i.test(trimmed)) return true;
  if (/^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(:\d+)?(\/.*)?$/i.test(trimmed)) return true;
  return false;
}

function isDangerousScheme(urlString) {
  if (!urlString) return false;
  const lower = String(urlString).trim().toLowerCase();
  for (const scheme of DANGEROUS_SCHEMES) {
    if (lower.startsWith(scheme)) return true;
  }
  return false;
}

function extractDomain(urlString) {
  if (!urlString) return null;
  let str = String(urlString).trim();
  if (!/^https?:\/\//i.test(str)) str = `http://${str}`;
  try {
    const parsed = new URL(str);
    return cleanDomain(parsed.hostname);
  } catch {
    return null;
  }
}

// Check domain via Cloudflare Security DNS over HTTPS (1.1.1.2)
// Cloudflare blocks malware, phishing, and C2 domains by returning 0.0.0.0 or Censored status.
async function checkCloudflareDoH(domain, timeoutMs = 2500) {
  if (!domain) return { safe: true };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const endpoint = `https://security.cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`;
    const response = await fetch(endpoint, {
      headers: { accept: 'application/dns-json' },
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) return { safe: true, unverified: true };
    const data = await response.json();

    // Check for 0.0.0.0 or censorship flags indicating malware block
    const answers = data.Answer || [];
    const isBlocked = answers.some((ans) => ans.data === '0.0.0.0') ||
                      (data.Comment && data.Comment.some((c) => /censored|blocked|filtered/i.test(c)));

    if (isBlocked) {
      return {
        safe: false,
        domain,
        reason: 'Flagged as malicious/phishing by threat intelligence (Cloudflare Security)',
        provider: 'cloudflare-doh'
      };
    }

    return { safe: true, domain };
  } catch {
    clearTimeout(timer);
    return { safe: true, unverified: true };
  }
}

// Google Safe Browsing API v4 check
async function checkGoogleSafeBrowsing(urlString, apiKey, timeoutMs = 3000) {
  if (!apiKey || !urlString) return { safe: true };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
    const body = {
      client: { clientId: 'lefty-assistant', clientVersion: '0.1.6' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['WINDOWS', 'ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url: urlString }]
      }
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    clearTimeout(timer);

    if (!response.ok) return { safe: true, unverified: true };
    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      const match = data.matches[0];
      return {
        safe: false,
        domain: extractDomain(urlString),
        reason: `Flagged as ${match.threatType.replace(/_/g, ' ').toLowerCase()} by Google Safe Browsing`,
        provider: 'google-safebrowsing'
      };
    }

    return { safe: true };
  } catch {
    clearTimeout(timer);
    return { safe: true, unverified: true };
  }
}

// Main URL verification function
async function checkUrl(urlString, options = {}) {
  if (!urlString) return { safe: true };
  const str = String(urlString).trim();

  // 1. Dangerous URI schemes
  if (isDangerousScheme(str)) {
    return {
      safe: false,
      risk: 'high',
      url: str,
      reason: 'Contains an unsafe or executable URI protocol scheme',
      provider: 'scheme-guard'
    };
  }

  const domain = extractDomain(str);
  if (!domain) return { safe: true };

  // 2. Punycode phishing check (e.g. xn--...)
  if (domain.includes(PUNYCODE_PREFIX)) {
    return {
      safe: false,
      risk: 'high',
      domain,
      reason: 'Contains deceptive Punycode / Internationalized Domain Name spoofing',
      provider: 'heuristic'
    };
  }

  // 3. Cache check
  const now = Date.now();
  const cached = reputationCache.get(domain);
  if (cached && now - cached.timestamp < CACHE_TTL_MS) {
    return cached.result;
  }

  // 4. Cloudflare Security DoH lookup
  const dohResult = await checkCloudflareDoH(domain, options.timeoutMs);
  if (!dohResult.safe) {
    const res = { safe: false, risk: 'high', domain, ...dohResult };
    reputationCache.set(domain, { timestamp: now, result: res });
    return res;
  }

  // 5. Optional Google Safe Browsing lookup
  const safeBrowsingKey = options.safeBrowsingKey || process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (safeBrowsingKey) {
    const sbResult = await checkGoogleSafeBrowsing(str, safeBrowsingKey, options.timeoutMs);
    if (!sbResult.safe) {
      const res = { safe: false, risk: 'high', domain, ...sbResult };
      reputationCache.set(domain, { timestamp: now, result: res });
      return res;
    }
  }

  const cleanResult = { safe: true, risk: 'none', domain };
  reputationCache.set(domain, { timestamp: now, result: cleanResult });
  return cleanResult;
}

module.exports = {
  checkUrl,
  checkCloudflareDoH,
  checkGoogleSafeBrowsing,
  extractUrl,
  extractDomain,
  isUrl,
  isDangerousScheme
};
