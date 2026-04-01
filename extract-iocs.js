#!/usr/bin/env node
/**
 * Breakglass Intelligence - IOC Extraction Script
 * Extracts all IOCs from published blog posts in the intel.db database
 * Generated: 2026-03-31
 */

const Database = require('/Users/jeffery/Desktop/breakglass-intel/node_modules/better-sqlite3');
const fs = require('fs');
const path = require('path');

const DB_PATH = '/Users/jeffery/Desktop/breakglass-intel/data/intel.db';
const OUTPUT_DIR = '/tmp/breakglass-intel-repo/iocs';
const BY_INVESTIGATION_DIR = path.join(OUTPUT_DIR, 'by-investigation');

// Ensure output directories exist
fs.mkdirSync(OUTPUT_DIR, { recursive: true });
fs.mkdirSync(BY_INVESTIGATION_DIR, { recursive: true });

const GENERATION_DATE = new Date().toISOString();
const HEADER = `# Breakglass Intelligence IOC Feed\n# Generated: ${GENERATION_DATE}\n# Source: https://intel.breakglass.tech\n# Repository: https://github.com/vuln/breakglass-intel\n#\n`;

// ---- Regex Patterns ----

// IPv4 - matches both defanged [.] and plain dots
// Excludes common version numbers and non-IP patterns
const IPV4_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\[\.\]|\.)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\[\.\]|\.)){2}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))\b/g;

// Domains - defanged or plain, must have valid TLD
const VALID_TLDS = 'com|net|org|io|tech|xyz|info|ru|cn|de|uk|fr|br|it|es|nl|pl|cz|ua|se|fi|no|dk|at|ch|be|pt|ro|hu|bg|hr|sk|si|lt|lv|ee|gr|tr|il|jp|kr|au|nz|in|pk|bd|sg|my|th|vn|ph|tw|hk|id|za|ng|ke|eg|ly|top|shop|site|online|club|live|me|cc|co|biz|us|ca|mx|ar|cl|pe|ve|bo|py|uy|ec|do|cr|sv|gt|hn|ni|pa|cu|pr|cloud|dev|app|gg|lol|win|bid|racing|download|stream|click|link|pro|space|fun|world|buzz|rest|surf|monster|gdn|cyou|icu|work|tk|ml|ga|cf|gq|tv|la|is|ws|one|to|ly|life|store|best|sbs|cfd|autos|homes|boats|yachts|motorcycles|apartments|in\\.net';
const DOMAIN_REGEX = new RegExp(
  '(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)(?:\\[?\\.\\]?)){1,10}(?:' + VALID_TLDS + ')\\b',
  'gi'
);

// URLs - defanged (hxxp, hxxps, [://]) or plain
const URL_REGEX = /(?:hxxps?|https?):?(?:\[:\])?\/\/[^\s<>"'\]){},]+/gi;

// Email addresses
const EMAIL_REGEX = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.(?:com|net|org|io|ru|de|uk|fr|br|info|tech|xyz|co|me|cc|biz|us|ca|au|jp|kr|cn|in|za|nl|it|es|pl|cz|ua|se|fi|no|dk|at|ch|be|pt|ro|hu|bg|hr|sk|si|lt|lv|ee|gr|tr|il)/gi;

// Hashes
const SHA256_REGEX = /\b[a-fA-F0-9]{64}\b/g;
const SHA1_REGEX = /\b[a-fA-F0-9]{40}\b/g;
const MD5_REGEX = /\b[a-fA-F0-9]{32}\b/g;

// File paths - Windows
const WIN_PATH_REGEX = /(?:[A-Z]:\\(?:[^\s\\:*?"<>|]+\\)*[^\s\\:*?"<>|]+)|(?:\\\\[^\s\\]+(?:\\[^\s\\]+)+)/gi;

// File paths - Linux/Unix
const LINUX_PATH_REGEX = /(?:\/(?:usr|etc|var|tmp|opt|home|root|proc|sys|dev|run|mnt|media|srv|boot|lib|lib64|sbin|bin)(?:\/[^\s<>"'`,;)\]}{]+)+)/g;

// Registry keys
const REGISTRY_REGEX = /(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\s<>"'`,;)\]]+/gi;

// Mutex names - typically in code blocks or after "mutex" keyword
const MUTEX_REGEX = /(?:mutex|mutant)[:\s]+["']?([a-zA-Z0-9_\-{}().]+)["']?/gi;

// Service names
const SERVICE_REGEX = /(?:service\s+name|sc\s+create|New-Service)[:\s]+["']?([a-zA-Z0-9_\-.]+)["']?/gi;

// Scheduled task names
const SCHTASK_REGEX = /(?:schtasks.*?\/tn\s+|scheduled\s+task[:\s]+)["']?([^\s"']+)["']?/gi;

// Filenames with common malware extensions
const FILENAME_REGEX = /\b[a-zA-Z0-9_\-.\[\](){}]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|msi|msp|scr|pif|com|lnk|jar|py|sh|php|asp|aspx|jsp|war|elf|so|dylib|dmg|app|pkg|deb|rpm|apk|ipa|doc|docx|docm|xls|xlsx|xlsm|ppt|pptx|pptm|rtf|pdf|iso|img|vhd|vhdx|mmc|inf|reg|cpl|ocx|cab|drv|tmp|dat|bin|raw|dump|log|conf|cfg|ini|xml|json|yaml|yml|sql|db|sqlite|bak|zip|rar|7z|tar|gz|bz2|xz|arj|lzh)\b/gi;

// ---- Helper Functions ----

function refangIP(ip) {
  return ip.replace(/\[\.\]/g, '.');
}

function defangIP(ip) {
  return ip.replace(/\./g, '[.]');
}

function refangURL(url) {
  return url.replace(/hxxp/gi, 'http').replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':');
}

function defangURL(url) {
  return url.replace(/http/gi, 'hxxp').replace(/\./g, '[.]').replace(/:\/\//g, '[://]');
}

function refangDomain(domain) {
  return domain.replace(/\[\.\]/g, '.').toLowerCase();
}

function isValidIP(ip) {
  const clean = refangIP(ip);
  const parts = clean.split('.');
  if (parts.length !== 4) return false;
  for (const p of parts) {
    const n = parseInt(p, 10);
    if (isNaN(n) || n < 0 || n > 255) return false;
  }
  // Exclude private, loopback, link-local, documentation ranges
  const first = parseInt(parts[0]);
  const second = parseInt(parts[1]);
  if (first === 0 || first === 127) return false;
  if (first === 10) return false;
  if (first === 172 && second >= 16 && second <= 31) return false;
  if (first === 192 && second === 168) return false;
  if (first === 169 && second === 254) return false;
  // Allow all other IPs including documentation ranges (some C2s use them for illustration)
  return true;
}

function isValidDomain(domain) {
  const clean = refangDomain(domain);
  // Filter out things that are clearly not domains
  if (clean.length < 4) return false;
  if (clean.startsWith('.') || clean.endsWith('.')) return false;
  // Filter version-like patterns (1.2.3.4 is IP, not domain)
  if (/^\d+\.\d+\.\d+\.\d+$/.test(clean)) return false;
  // Filter pure numeric subdomains that aren't real domains
  if (/^\d+\.\d+$/.test(clean)) return false;
  // Must have at least one non-numeric label
  const labels = clean.split('.');
  if (labels.every(l => /^\d+$/.test(l))) return false;
  // Must have a valid TLD
  const tld = labels[labels.length - 1].toLowerCase();
  if (tld.length < 2) return false;
  return true;
}

function isLikelyHash(h, len) {
  // Must be exactly the right length and all hex
  if (h.length !== len) return false;
  if (!/^[a-fA-F0-9]+$/.test(h)) return false;
  // Filter out strings that are all same char or all zeros
  if (/^(.)\1+$/.test(h)) return false;
  if (/^0+$/.test(h)) return false;
  // Filter hex strings that are clearly not hashes (like GUIDs for 32-char)
  return true;
}

// Filter out common false positive domains
const DOMAIN_BLACKLIST = new Set([
  'example.com', 'example.org', 'example.net', 'test.com', 'localhost.com',
  'github.com', 'githubusercontent.com', 'raw.githubusercontent.com',
  'google.com', 'youtube.com', 'twitter.com', 'x.com',
  'virustotal.com', 'malwarebazaar.com', 'abuse.ch', 'urlhaus.abuse.ch',
  'threatfox.abuse.ch', 'bazaar.abuse.ch', 'shodan.io', 'censys.io',
  'any.run', 'hybrid-analysis.com', 'joesandbox.com', 'triage.run',
  'microsoft.com', 'windows.com', 'apple.com', 'mozilla.org',
  'breakglass.tech', 'intel.breakglass.tech', 'breakglassintel.com',
  'cve.org', 'cve.mitre.org', 'nvd.nist.gov', 'attack.mitre.org',
  'linkedin.com', 'reddit.com', 'medium.com', 'wikipedia.org',
  'cloudflare.com', 'amazonaws.com', 'azure.com',
  'notion.so', 'notion.site', 'substack.com',
  'w3.org', 'schema.org', 'json-schema.org',
  'fonts.googleapis.com', 'fonts.gstatic.com',
  'maxcdn.bootstrapcdn.com', 'cdn.jsdelivr.net',
  'creativecommons.org', 'oasis-open.org',
  'docs.oasis-open.org', 'stix.mitre.org',
  'unpkg.com', 'cdnjs.cloudflare.com',
]);

// ---- Main Extraction ----

const db = new Database(DB_PATH, { readonly: true });
const posts = db.prepare("SELECT id, slug, title, content FROM posts WHERE status = 'published' ORDER BY id").all();

console.log(`Processing ${posts.length} published posts...`);

const allIPv4 = new Set();
const allDomains = new Set();
const allURLs = new Set();
const allEmails = new Set();
const allSHA256 = new Set();
const allSHA1 = new Set();
const allMD5 = new Set();
const allFilenames = new Set();
const allWinPaths = new Set();
const allLinuxPaths = new Set();
const allRegistryKeys = new Set();
const allMutexes = new Set();
const allServices = new Set();
const allSchedTasks = new Set();

const investigations = [];

for (const post of posts) {
  const content = post.content || '';

  const postIOCs = {
    ipv4: new Set(),
    domains: new Set(),
    urls: new Set(),
    emails: new Set(),
    sha256: new Set(),
    sha1: new Set(),
    md5: new Set(),
    filenames: new Set(),
    win_paths: new Set(),
    linux_paths: new Set(),
    registry_keys: new Set(),
    mutexes: new Set(),
    services: new Set(),
    scheduled_tasks: new Set(),
  };

  // Extract IPv4
  let match;
  const ipMatches = content.match(IPV4_REGEX) || [];
  for (const ip of ipMatches) {
    const clean = refangIP(ip);
    if (isValidIP(clean)) {
      postIOCs.ipv4.add(clean);
      allIPv4.add(clean);
    }
  }

  // Extract URLs (before domains, so we can filter domain FPs)
  const urlMatches = content.match(URL_REGEX) || [];
  for (const url of urlMatches) {
    const cleaned = url.replace(/[)\]},;'"]+$/, ''); // trim trailing punctuation
    postIOCs.urls.add(cleaned);
    allURLs.add(cleaned);
  }

  // Extract domains
  const domainMatches = content.match(DOMAIN_REGEX) || [];
  for (const d of domainMatches) {
    const clean = refangDomain(d);
    if (isValidDomain(clean) && !DOMAIN_BLACKLIST.has(clean)) {
      // Check if it's not just an IP
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(clean)) {
        postIOCs.domains.add(clean);
        allDomains.add(clean);
      }
    }
  }

  // Extract emails
  const emailMatches = content.match(EMAIL_REGEX) || [];
  for (const e of emailMatches) {
    postIOCs.emails.add(e.toLowerCase());
    allEmails.add(e.toLowerCase());
  }

  // Extract SHA256 (do this before SHA1 and MD5 to avoid substring matches)
  const sha256Matches = content.match(SHA256_REGEX) || [];
  const sha256Set = new Set();
  for (const h of sha256Matches) {
    if (isLikelyHash(h, 64)) {
      const lower = h.toLowerCase();
      sha256Set.add(lower);
      postIOCs.sha256.add(lower);
      allSHA256.add(lower);
    }
  }

  // Extract SHA1 - exclude substrings of SHA256
  const sha1Candidates = content.match(SHA1_REGEX) || [];
  for (const h of sha1Candidates) {
    if (h.length === 40 && isLikelyHash(h, 40)) {
      const lower = h.toLowerCase();
      // Check it's not a substring of a known SHA256
      let isSub = false;
      for (const s256 of sha256Set) {
        if (s256.includes(lower)) { isSub = true; break; }
      }
      if (!isSub) {
        postIOCs.sha1.add(lower);
        allSHA1.add(lower);
      }
    }
  }

  // Extract MD5 - exclude substrings of SHA256 and SHA1
  const md5Candidates = content.match(MD5_REGEX) || [];
  const sha1Set = new Set(postIOCs.sha1);
  for (const h of md5Candidates) {
    if (h.length === 32 && isLikelyHash(h, 32)) {
      const lower = h.toLowerCase();
      let isSub = false;
      for (const s256 of sha256Set) {
        if (s256.includes(lower)) { isSub = true; break; }
      }
      if (!isSub) {
        for (const s1 of sha1Set) {
          if (s1.includes(lower)) { isSub = true; break; }
        }
      }
      if (!isSub) {
        postIOCs.md5.add(lower);
        allMD5.add(lower);
      }
    }
  }

  // Extract filenames
  const filenameMatches = content.match(FILENAME_REGEX) || [];
  for (const f of filenameMatches) {
    // Filter out common library/framework files
    if (!/^(?:jquery|bootstrap|angular|react|vue|webpack|babel|eslint|prettier|typescript)\./i.test(f)) {
      postIOCs.filenames.add(f);
      allFilenames.add(f);
    }
  }

  // Extract Windows paths
  const winPathMatches = content.match(WIN_PATH_REGEX) || [];
  for (const p of winPathMatches) {
    postIOCs.win_paths.add(p);
    allWinPaths.add(p);
  }

  // Extract Linux paths
  const linuxPathMatches = content.match(LINUX_PATH_REGEX) || [];
  for (const p of linuxPathMatches) {
    postIOCs.linux_paths.add(p);
    allLinuxPaths.add(p);
  }

  // Extract registry keys
  const regMatches = content.match(REGISTRY_REGEX) || [];
  for (const r of regMatches) {
    postIOCs.registry_keys.add(r);
    allRegistryKeys.add(r);
  }

  // Extract mutexes
  while ((match = MUTEX_REGEX.exec(content)) !== null) {
    postIOCs.mutexes.add(match[1]);
    allMutexes.add(match[1]);
  }

  // Extract service names
  while ((match = SERVICE_REGEX.exec(content)) !== null) {
    postIOCs.services.add(match[1]);
    allServices.add(match[1]);
  }

  // Extract scheduled tasks
  while ((match = SCHTASK_REGEX.exec(content)) !== null) {
    postIOCs.scheduled_tasks.add(match[1]);
    allSchedTasks.add(match[1]);
  }

  // Count total IOCs for this post
  const iocCount =
    postIOCs.ipv4.size + postIOCs.domains.size + postIOCs.urls.size +
    postIOCs.emails.size + postIOCs.sha256.size + postIOCs.sha1.size +
    postIOCs.md5.size + postIOCs.filenames.size;

  investigations.push({
    id: post.id,
    slug: post.slug,
    title: post.title,
    ioc_count: iocCount,
  });

  // Write per-investigation JSON if there are IOCs
  if (iocCount > 0) {
    const investigationData = {
      investigation: {
        id: post.id,
        slug: post.slug,
        title: post.title,
        url: `https://intel.breakglass.tech/blog/${post.slug}`,
      },
      generated: GENERATION_DATE,
      network_iocs: {
        ipv4: [...postIOCs.ipv4].sort(),
        domains: [...postIOCs.domains].sort(),
        urls: [...postIOCs.urls].sort(),
        emails: [...postIOCs.emails].sort(),
      },
      file_hashes: {
        sha256: [...postIOCs.sha256].sort(),
        sha1: [...postIOCs.sha1].sort(),
        md5: [...postIOCs.md5].sort(),
      },
      host_indicators: {
        filenames: [...postIOCs.filenames].sort(),
        windows_paths: [...postIOCs.win_paths].sort(),
        linux_paths: [...postIOCs.linux_paths].sort(),
        registry_keys: [...postIOCs.registry_keys].sort(),
        mutexes: [...postIOCs.mutexes].sort(),
        services: [...postIOCs.services].sort(),
        scheduled_tasks: [...postIOCs.scheduled_tasks].sort(),
      },
      summary: {
        total_iocs: iocCount,
        ipv4_count: postIOCs.ipv4.size,
        domain_count: postIOCs.domains.size,
        url_count: postIOCs.urls.size,
        sha256_count: postIOCs.sha256.size,
        sha1_count: postIOCs.sha1.size,
        md5_count: postIOCs.md5.size,
        filename_count: postIOCs.filenames.size,
      },
    };

    fs.writeFileSync(
      path.join(BY_INVESTIGATION_DIR, `${post.slug}.json`),
      JSON.stringify(investigationData, null, 2)
    );
  }
}

db.close();

// ---- Write aggregated files ----

// IPv4
const sortedIPs = [...allIPv4].sort((a, b) => {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 4; i++) {
    if (pa[i] !== pb[i]) return pa[i] - pb[i];
  }
  return 0;
});
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'all-ipv4.txt'),
  HEADER + sortedIPs.join('\n') + '\n'
);

// Domains
const sortedDomains = [...allDomains].sort();
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'all-domains.txt'),
  HEADER + sortedDomains.join('\n') + '\n'
);

// URLs (defanged)
const defangedURLs = [...allURLs].map(u => {
  // Defang for safety
  return u.replace(/http/gi, 'hxxp');
}).sort();
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'all-urls.txt'),
  HEADER + defangedURLs.join('\n') + '\n'
);

// SHA256
const sortedSHA256 = [...allSHA256].sort();
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'all-sha256.txt'),
  HEADER + sortedSHA256.join('\n') + '\n'
);

// SHA1
const sortedSHA1 = [...allSHA1].sort();
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'all-sha1.txt'),
  HEADER + sortedSHA1.join('\n') + '\n'
);

// MD5
const sortedMD5 = [...allMD5].sort();
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'all-md5.txt'),
  HEADER + sortedMD5.join('\n') + '\n'
);

// File indicators JSON
const fileIndicators = {
  generated: GENERATION_DATE,
  source: 'https://intel.breakglass.tech',
  filenames: [...allFilenames].sort(),
  windows_paths: [...allWinPaths].sort(),
  linux_paths: [...allLinuxPaths].sort(),
  registry_keys: [...allRegistryKeys].sort(),
  mutexes: [...allMutexes].sort(),
  services: [...allServices].sort(),
  scheduled_tasks: [...allSchedTasks].sort(),
  emails: [...allEmails].sort(),
};
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'all-file-indicators.json'),
  JSON.stringify(fileIndicators, null, 2)
);

// Feed index
const feed = {
  name: 'Breakglass Intelligence IOC Feed',
  url: 'https://github.com/vuln/breakglass-intel',
  website: 'https://intel.breakglass.tech',
  generated: GENERATION_DATE,
  total_indicators: {
    ipv4: allIPv4.size,
    domains: allDomains.size,
    urls: allURLs.size,
    sha256: allSHA256.size,
    sha1: allSHA1.size,
    md5: allMD5.size,
  },
  investigations: investigations,
};
fs.writeFileSync(
  path.join(OUTPUT_DIR, 'feed.json'),
  JSON.stringify(feed, null, 2)
);

// ---- Summary ----
console.log('\n=== IOC Extraction Complete ===');
console.log(`Posts processed: ${posts.length}`);
console.log(`Posts with IOCs: ${investigations.filter(i => i.ioc_count > 0).length}`);
console.log(`\nNetwork IOCs:`);
console.log(`  IPv4 addresses: ${allIPv4.size}`);
console.log(`  Domains: ${allDomains.size}`);
console.log(`  URLs: ${allURLs.size}`);
console.log(`  Emails: ${allEmails.size}`);
console.log(`\nFile Hashes:`);
console.log(`  SHA256: ${allSHA256.size}`);
console.log(`  SHA1: ${allSHA1.size}`);
console.log(`  MD5: ${allMD5.size}`);
console.log(`\nHost Indicators:`);
console.log(`  Filenames: ${allFilenames.size}`);
console.log(`  Windows paths: ${allWinPaths.size}`);
console.log(`  Linux paths: ${allLinuxPaths.size}`);
console.log(`  Registry keys: ${allRegistryKeys.size}`);
console.log(`  Mutexes: ${allMutexes.size}`);
console.log(`  Services: ${allServices.size}`);
console.log(`  Scheduled tasks: ${allSchedTasks.size}`);
console.log(`\nOutput files written to: ${OUTPUT_DIR}/`);
