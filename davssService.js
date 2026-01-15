/**
 * DAVSS Service - Domain-Affinity Visual Similarity Scoring
 * 
 * This module detects brand impersonation by:
 * 1. Capturing a screenshot of the current page
 * 2. Uploading it to ImgBB to get a public URL
 * 3. Using SerpApi (Google Lens) to find visually similar images
 * 4. Analyzing the top search results to check if they match the current domain
 * 
 * If the most frequent domain in results differs from the current domain,
 * it indicates potential brand impersonation.
 */

/**
 * API Keys - TODO: Store these in chrome.storage.local for better security
 */
const IMGBB_API_KEY = 'fd7077fb381de903b0f53d11e0269a07';
//const SERPAPI_KEY = '081207b3c5172c4c497812a945b99718c9aebe553d19b09085ece1884dd5e9df';
//use above key again in a month
const SERPAPI_KEY = 'af54b86e7272726271820455c44ba5f9a51918e10b47f6f4c6726bae1901c2c9';

/**
 * Configuration for Weighted Evidence Pipeline
 * 
 * This architecture uses signal-based detection instead of complex scoring.
 * Signals are extracted from visual matches and evaluated against scenarios.
 */
const CONFIG = {
  // Safe TLDs - Trusted top-level domains
  SAFE_TLDS: new Set([
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'ai', 'co', 'me', 'app', 'dev',
    'uk', 'us', 'ca', 'au', 'nz', 'in', 'de', 'fr', 'it', 'es', 'nl', 'ch', 'se',
    'no', 'dk', 'fi', 'jp', 'cn', 'kr', 'sg', 'br', 'mx', 'ru', 'za'
  ]),

  // Risky TLDs - Often used for phishing
  RISKY_TLDS: new Set([
    'la', 'xyz', 'top', 'vip', 'pro', 'info', 'live', 'club', 'online', 'site',
    'tk', 'ml', 'ga', 'cf', 'gq', 'bid', 'win', 'stream', 'download', 'party'
  ]),

  // Noisy Domains - Platforms that host content about other brands
  NOISY_DOMAINS: new Set([
    'youtube.com', 'facebook.com', 'instagram.com', 'linkedin.com', 'pinterest.com',
    'twitter.com', 'x.com', 'reddit.com', 'wikipedia.org', 'en.wikipedia.org',
    'medium.com', 'cnet.com', 'softpedia.com', 'uptodown.com', 'apkpure.com',
    'play.google.com', 'apps.apple.com', 'bing.com', 'google.com',
    'amazon.com', 'ebay.com', 'etsy.com', 'trustpilot.com', 'yelp.com'
  ]),

  // Priority Brands - High-profile targets that require extra scrutiny
  PRIORITY_BRANDS: new Set([
    'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram',
    'roblox', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'netflix',
    'dropbox', 'adobe', 'binance', 'coinbase', 'kraken', 'trezor', 'ledger',
    'metamask', 'steam', 'epicgames', 'discord', 'twitter', 'linkedin',
    'spotify', 'twitch', 'youtube', 'gmail', 'outlook', 'icloud'
  ])
};

/**
 * Retrieves API keys from storage or uses defaults
 * 
 * @returns {Promise<Object>} - Object with { imgbbKey, serpapiKey }
 */
async function getApiKeys() {
  try {
    const result = await chrome.storage.local.get(['imgbbApiKey', 'serpapiKey']);
    return {
      imgbbKey: result.imgbbApiKey || IMGBB_API_KEY,
      serpapiKey: result.serpapiKey || SERPAPI_KEY
    };
  } catch (error) {
    console.warn('Could not retrieve API keys from storage:', error);
    return {
      imgbbKey: IMGBB_API_KEY,
      serpapiKey: SERPAPI_KEY
    };
  }
}

/**
 * Weighted Evidence Pipeline - Helper 1: Robust URL Parser
 * 
 * Parses URLs and extracts brand name, TLD, and hostname with proper handling
 * of multi-part TLDs (co.uk, com.au, bank.in, etc.)
 * 
 * @param {string} urlStr - URL to parse
 * @returns {Object} - { hostname, brand, tld, isValid }
 */
function parseUrlDetails(urlStr) {
  try {
    // Handle both full URLs and hostnames
    let url;
    if (urlStr.startsWith('http://') || urlStr.startsWith('https://')) {
      url = new URL(urlStr);
    } else {
      url = new URL('https://' + urlStr);
    }

    const hostname = url.hostname.toLowerCase().replace(/^www\./, '');
    const parts = hostname.split('.');

    if (parts.length < 2) {
      return { isValid: false };
    }

    // Extract TLD (handle multi-part TLDs)
    let tld = parts[parts.length - 1];
    let brandIndex = parts.length - 2;

    // Check for multi-part TLDs (co.uk, com.au, bank.in, etc.)
    if (parts.length >= 3) {
      const secondLastPart = parts[parts.length - 2];
      const possibleMultiPartTLD = secondLastPart + '.' + tld;

      // Common multi-part TLD patterns
      const multiPartTLDs = ['co.uk', 'co.in', 'co.jp', 'co.kr', 'co.nz', 'co.za',
        'com.au', 'com.br', 'com.mx', 'com.ar', 'com.cn', 'com.tw', 'com.hk',
        'org.uk', 'net.uk', 'ac.uk', 'gov.uk', 'bank.in', 'net.in', 'org.in'];

      if (multiPartTLDs.includes(possibleMultiPartTLD)) {
        tld = possibleMultiPartTLD;
        brandIndex = parts.length - 3;
      }
    }

    // Extract brand (the part before TLD)
    const brand = brandIndex >= 0 ? parts[brandIndex] : parts[0];

    return {
      hostname,
      brand: brand.toLowerCase(),
      tld: tld.toLowerCase(),
      isValid: true
    };

  } catch (e) {
    console.warn('[DAVSS] Error parsing URL:', urlStr, e);
    return { isValid: false };
  }
}

/**
 * Weighted Evidence Pipeline - Helper 2: Signal Extraction
 * 
 * Analyzes visual matches and extracts evidence signals instead of calculating scores.
 * This decouples detection from scoring, making logic more maintainable.
 * 
 * @param {Array} visualMatches - Array of visual match results from SerpApi
 * @param {Object} currentDetails - Parsed details of current URL
 * @returns {Object} - Signal object with evidence flags
 */
function extractSignals(visualMatches, currentDetails) {
  const signals = {
    foundPriorityBrand: false,     // Did we see a high-profile brand (PayPal, Instagram)?
    visualDomainMatch: false,      // Does current domain appear in results?
    titleKeywordMatch: false,      // Do result titles mention current brand?
    detectedTrueDomain: null,      // Best candidate for the "real" domain
    priorityBrandName: null,       // Name of priority brand found
    totalMatches: visualMatches.length
  };

  const { brand: currentBrand, hostname: currentHost } = currentDetails;

  console.log('[DAVSS] ðŸ” Extracting signals for brand:', currentBrand);

  // Scan all visual matches for evidence
  for (const match of visualMatches) {
    const link = match.link || match.source || '';
    const title = (match.title || '').toLowerCase();

    if (!link) continue;

    const resultDetails = parseUrlDetails(link);
    if (!resultDetails.isValid) continue;

    const resultDomain = resultDetails.hostname;
    const resultBrand = resultDetails.brand;

    // Skip noisy domains (they don't count as "candidates")
    if (CONFIG.NOISY_DOMAINS.has(resultDomain)) {
      console.log('[DAVSS] Skipping noisy domain:', resultDomain);
      continue;
    }

    // SIGNAL A: Direct Domain Match
    if (resultDomain === currentHost) {
      signals.visualDomainMatch = true;
      console.log('[DAVSS] âœ“ Visual Domain Match:', resultDomain);
    }

    // SIGNAL B: Priority Brand Detection (Expert Witness)
    if (CONFIG.PRIORITY_BRANDS.has(resultBrand)) {
      signals.foundPriorityBrand = true;
      signals.detectedTrueDomain = resultDomain;
      signals.priorityBrandName = resultBrand;
      console.log('[DAVSS] ðŸŽ¯ Priority Brand Detected:', resultBrand, 'â†’', resultDomain);
    }

    // SIGNAL C: Title Keyword Match (Contextual Validation)
    if (title && title.includes(currentBrand)) {
      signals.titleKeywordMatch = true;
      console.log('[DAVSS] âœ“ Title mentions current brand:', title);
    }
  }

  console.log('[DAVSS] Signal Summary:', signals);
  return signals;
}

/**
 * Standardizes a domain by removing 'www.' prefix and extracting core domain
 * 
 * @param {string} domain - The domain string to standardize
 * @returns {string} - Standardized domain (e.g., 'www.google.com' -> 'google.com')
 */
function standardizeDomain(domain) {
  if (!domain) return '';

  try {
    // Remove protocol if present
    let cleanDomain = domain.replace(/^https?:\/\//, '');

    // Remove 'www.' prefix (case-insensitive)
    cleanDomain = cleanDomain.replace(/^www\./i, '');

    // Extract just the hostname (remove path, query, fragment)
    const url = new URL(cleanDomain.startsWith('http') ? cleanDomain : `https://${cleanDomain}`);
    let hostname = url.hostname;

    // Remove 'www.' again in case it was part of the hostname
    hostname = hostname.replace(/^www\./i, '');

    return hostname.toLowerCase();
  } catch (error) {
    // If URL parsing fails, try simple string manipulation
    let cleanDomain = domain.toLowerCase();
    cleanDomain = cleanDomain.replace(/^https?:\/\//, '');
    cleanDomain = cleanDomain.replace(/^www\./i, '');
    cleanDomain = cleanDomain.split('/')[0]; // Remove path
    cleanDomain = cleanDomain.split('?')[0]; // Remove query
    cleanDomain = cleanDomain.split('#')[0]; // Remove fragment
    return cleanDomain;
  }
}

/**
 * Extracts the root domain (eTLD+1) from a hostname, handling complex TLDs
 * 
 * Security-grade domain extraction that correctly handles:
 * - Simple TLDs: example.com -> example.com
 * - Complex TLDs: amazon.co.uk -> amazon.co.uk
 * - IP addresses: 192.168.1.1 -> 192.168.1.1 (returned as-is)
 * 
 * @param {string} hostname - The hostname string (e.g., "store.steampowered.com" or "amazon.co.uk")
 * @returns {string} - Root domain (eTLD+1) (e.g., "steampowered.com" or "amazon.co.uk")
 */
function extractRootDomain(hostname) {
  if (!hostname) return '';

  // Remove www. prefix if present
  let cleanHostname = hostname.toLowerCase().replace(/^www\./i, '');

  // Edge Case: Check if it's an IP address
  const ipPattern = /^\d{1,3}(\.\d{1,3}){3}$/;
  if (ipPattern.test(cleanHostname)) {
    return cleanHostname; // Return IP as-is
  }

  // Define common Second Level TLDs (SLDs) that require special handling
  const secondLevelTLDs = [
    '.co.uk', '.gov.uk', '.ac.uk', '.org.uk', '.net.uk',
    '.ac.in', '.co.in', '.gov.in', '.net.in', '.org.in',
    '.com.au', '.net.au', '.org.au', '.edu.au', '.gov.au',
    '.com.br', '.net.br', '.org.br', '.gov.br',
    '.co.jp', '.ne.jp', '.or.jp', '.ac.jp', '.go.jp',
    '.co.kr', '.or.kr', '.ac.kr',
    '.com.cn', '.net.cn', '.org.cn', '.gov.cn', '.edu.cn',
    '.com.tw', '.org.tw', '.edu.tw', '.gov.tw',
    '.com.hk', '.org.hk', '.edu.hk', '.gov.hk',
    '.com.sg', '.org.sg', '.edu.sg', '.gov.sg',
    '.com.my', '.org.my', '.edu.my', '.gov.my',
    '.com.ph', '.org.ph', '.edu.ph', '.gov.ph',
    '.com.id', '.org.id', '.edu.id', '.gov.id',
    '.com.th', '.org.th', '.edu.th', '.gov.th',
    '.com.vn', '.org.vn', '.edu.vn', '.gov.vn'
  ];

  // Check if the hostname ends with a known second-level TLD
  let matchedSLD = null;
  for (const sld of secondLevelTLDs) {
    if (cleanHostname.endsWith(sld)) {
      matchedSLD = sld;
      break;
    }
  }

  // Split by dots
  const parts = cleanHostname.split('.');

  if (matchedSLD) {
    // For second-level TLDs, take the last 3 parts
    // e.g., "amazon.co.uk" -> ["amazon", "co", "uk"] -> "amazon.co.uk"
    if (parts.length >= 3) {
      return parts.slice(-3).join('.');
    } else {
      return cleanHostname; // Fallback if not enough parts
    }
  } else {
    // For standard TLDs, take the last 2 parts
    // e.g., "store.steampowered.com" -> ["store", "steampowered", "com"] -> "steampowered.com"
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    } else {
      return cleanHostname; // Fallback if not enough parts
    }
  }
}

/**
 * Extracts the brand name (first part) from a root domain
 * 
 * Used for brand-based comparison that allows cross-TLD matches:
 * - amazon.co.uk -> "amazon"
 * - amazon.com -> "amazon"
 * - roblox.com -> "roblox"
 * 
 * @param {string} rootDomain - The root domain (e.g., "amazon.co.uk" or "roblox.com")
 * @returns {string} - The brand name (first part before TLD)
 */
function extractBrand(rootDomain) {
  if (!rootDomain) return '';

  // Split by dots and take the first part
  const parts = rootDomain.split('.');
  if (parts.length > 0) {
    return parts[0].toLowerCase();
  }
  return rootDomain.toLowerCase();
}

/**
 * Extracts the brand name from a URL for title verification
 * 
 * Removes common prefixes (www, secure, login, account, my) and TLDs
 * to get the core brand identity for matching against search result titles.
 * 
 * Examples:
 * - https://www.delhivery.com â†’ "delhivery"
 * - https://secure.login.microsoft.com â†’ "microsoft"
 * - https://free-robux-scam.com â†’ "free-robux-scam"
 * 
 * @param {string} url - Full URL or hostname
 * @returns {string} - Normalized brand name
 */
function extractBrandName(url) {
  if (!url) return '';

  try {
    // Parse URL to get hostname
    let hostname = url;
    if (url.startsWith('http://') || url.startsWith('https://')) {
      const urlObj = new URL(url);
      hostname = urlObj.hostname;
    }

    // Remove common prefixes (case-insensitive)
    hostname = hostname.toLowerCase();
    hostname = hostname.replace(/^www\./, '');
    hostname = hostname.replace(/^secure\./, '');
    hostname = hostname.replace(/^login\./, '');
    hostname = hostname.replace(/^account\./, '');
    hostname = hostname.replace(/^my\./, '');
    hostname = hostname.replace(/^app\./, '');

    // Extract domain before TLD (handle multi-part TLDs)
    const parts = hostname.split('.');

    // For multi-part TLDs (e.g., co.uk), take second-to-last part
    // For standard TLDs, take first part
    if (parts.length >= 3) {
      // Check if last two parts form known TLD (co.uk, com.au, etc.)
      const lastTwo = parts.slice(-2).join('.');
      const multiPartTLDs = ['co.uk', 'com.au', 'co.in', 'co.jp', 'com.br'];
      if (multiPartTLDs.includes(lastTwo)) {
        // Take third-from-last part (domain name)
        return parts[parts.length - 3];
      }
    }

    // Standard case: take first part (before TLD)
    return parts[0];

  } catch (error) {
    console.warn('[DAVSS] Error extracting brand name:', error);
    return '';
  }
}

/**
 * Get logo coordinates from the active page by running a DOM heuristic.
 * Uses chrome.scripting.executeScript to run in the page context.
 *
 * @param {number} tabId - The tab to inspect.
 * @returns {Promise<{rect: {x:number,y:number,width:number,height:number}, dpr:number} | null>}
 */
async function getLogoCoordinates(tabId) {
  try {
    const [{ result }] = await chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        const MIN_SCORE = 20;
        const KEYWORD_SCORE = 10;
        const TOP_SCORE = 20;
        const LINK_SCORE = 15;
        const TOP_BOUNDARY = 150; // px
        const MIN_WIDTH = 20;
        const MAX_WIDTH = 600;
        const MAX_HEIGHT = 200;
        const KEYWORDS = ['logo', 'brand', 'header', 'nav'];

        const matchesKeywords = (str = '') => {
          const lower = str.toLowerCase();
          return KEYWORDS.some((kw) => lower.includes(kw));
        };

        const isRootLink = (anchor, currentDomain) => {
          if (!anchor || !anchor.href) return false;
          try {
            const url = new URL(anchor.href, window.location.href);
            if (url.origin !== window.location.origin) return false;
            if (url.pathname === '/' || url.pathname === '' || url.href === window.location.origin + '/') {
              return true;
            }
            if (url.pathname === '/' && (url.search || url.hash)) {
              return true;
            }
            if (currentDomain && url.hostname === currentDomain && url.pathname === '/') {
              return true;
            }
          } catch (_) {
            return false;
          }
          return false;
        };

        const getBackgroundImageCandidates = () => {
          const nodes = Array.from(document.querySelectorAll('*'));
          return nodes.filter((el) => {
            const style = getComputedStyle(el);
            const bg = style.backgroundImage;
            if (!bg || bg === 'none') return false;
            if (bg.includes('gradient')) return false;
            return true;
          });
        };

        const elementScore = (el, currentDomain) => {
          if (!el || typeof el.getBoundingClientRect !== 'function') return -Infinity;
          const rect = el.getBoundingClientRect();
          const width = rect.width;
          const height = rect.height;
          if (width < MIN_WIDTH || width > MAX_WIDTH) return -Infinity;
          if (height > MAX_HEIGHT) return -Infinity;
          let score = 0;
          const idClass = `${el.id || ''} ${el.className || ''}`;
          const alt = el.alt || '';
          const src = el.src || '';
          if (matchesKeywords(idClass) || matchesKeywords(alt) || matchesKeywords(src)) {
            score += KEYWORD_SCORE;
          }
          if (rect.top >= 0 && rect.top <= TOP_BOUNDARY) {
            score += TOP_SCORE;
          }
          const anchor = el.closest('a');
          if (isRootLink(anchor, window.location.hostname)) {
            score += LINK_SCORE;
          }
          return score;
        };

        const candidates = [];
        candidates.push(...Array.from(document.images));
        candidates.push(...Array.from(document.querySelectorAll('svg')));
        candidates.push(...getBackgroundImageCandidates());

        let best = null;
        let bestScore = -Infinity;
        for (const el of candidates) {
          const score = elementScore(el, window.location.hostname);
          if (score > bestScore) {
            bestScore = score;
            best = el;
          }
        }

        if (!best || bestScore < MIN_SCORE) return null;
        const rect = best.getBoundingClientRect();
        return {
          rect: { x: rect.x, y: rect.y, width: rect.width, height: rect.height },
          dpr: window.devicePixelRatio || 1
        };
      }
    });
    return result || null;
  } catch (err) {
    console.warn('[DAVSS] Logo detection failed:', err);
    return null;
  }
}

/**
 * Crops a screenshot dataURL to the given rectangle using OffscreenCanvas.
 * Coordinates are in CSS pixels; we scale by devicePixelRatio to match image pixels.
 *
 * @param {string} dataUrl - Full screenshot data URL (png)
 * @param {{x:number,y:number,width:number,height:number}} rect - bounding box in CSS px
 * @param {number} dpr - device pixel ratio
 * @returns {Promise<string>} - Cropped image as data URL
 */
async function cropImageToRect(dataUrl, rect, dpr = 1) {
  const padding = 10;
  const scale = dpr || 1;
  const sx = Math.max(0, rect.x * scale - padding * scale);
  const sy = Math.max(0, rect.y * scale - padding * scale);
  const sWidth = Math.max(1, rect.width * scale + padding * 2 * scale);
  const sHeight = Math.max(1, rect.height * scale + padding * 2 * scale);

  const response = await fetch(dataUrl);
  const blob = await response.blob();
  const bitmap = await createImageBitmap(blob);

  const cropWidth = Math.min(sWidth, bitmap.width - sx);
  const cropHeight = Math.min(sHeight, bitmap.height - sy);

  const canvas = new OffscreenCanvas(cropWidth, cropHeight);
  const ctx = canvas.getContext('2d');
  ctx.drawImage(bitmap, sx, sy, cropWidth, cropHeight, 0, 0, cropWidth, cropHeight);

  const croppedBlob = await canvas.convertToBlob({ type: 'image/png', quality: 1 });
  const croppedDataUrl = await new Promise((resolve) => {
    const reader = new FileReader();
    reader.onloadend = () => resolve(reader.result);
    reader.readAsDataURL(croppedBlob);
  });
  return croppedDataUrl;
}

/**
 * Safe TLDs Whitelist
 * 
 * Trusted TLDs that are commonly used by legitimate organizations.
 * If a brand match occurs but the current URL uses a TLD NOT in this list,
 * it's flagged as suspicious (e.g., paypal.vip, amazon.xyz).
 */
const SAFE_TLDS = new Set([
  // The Big Three
  'com', 'org', 'net',

  // Institutional
  'edu', 'gov', 'mil', 'int', 'io', 'ai', 'co', 'me', 'app', 'dev',

  // Common Country Codes (Top 20 GDP + English speaking)
  // English/Commonwealth
  'uk', 'us', 'ca', 'au', 'nz', 'in',

  // Europe
  'de', 'fr', 'it', 'es', 'nl', 'ch', 'se', 'no', 'dk', 'fi',

  // Asia/ROW
  'jp', 'cn', 'kr', 'sg', 'br', 'mx', 'ru', 'za'
]);

/**
 * Extracts the TLD from a root domain for whitelist checking
 * 
 * Handles multi-part TLDs correctly:
 * - amazon.co.uk -> "uk" (checks last part)
 * - amazon.com -> "com"
 * - paypal.vip -> "vip"
 * 
 * @param {string} rootDomain - The root domain (e.g., "amazon.co.uk" or "paypal.com")
 * @returns {string} - The TLD to check (last part for multi-part TLDs)
 */
function extractTLD(rootDomain) {
  if (!rootDomain) return '';

  // Split by dots
  const parts = rootDomain.toLowerCase().split('.');

  if (parts.length === 0) return '';

  // For multi-part TLDs like "co.uk", we check the last part ("uk")
  // This handles cases like amazon.co.uk -> checks "uk"
  return parts[parts.length - 1];
}

/**
 * Noisy Domains Set
 * 
 * These are social media, content platforms, design/portfolio sites, tech news, and download sites
 * that frequently appear in visual search results (e.g., YouTube videos of product reviews, 
 * Figma templates, CNET articles, app stores, etc.) but are not the actual brand domain being scanned.
 * We filter these out unless they are the ONLY results.
 */
const NOISY_DOMAINS = new Set([
  // Social Media (The usual suspects)
  'youtube.com',
  'www.youtube.com',
  'facebook.com',
  'www.facebook.com',
  'instagram.com',
  'www.instagram.com',
  'pinterest.com',
  'www.pinterest.com',
  'twitter.com',
  'x.com',
  'linkedin.com',
  'reddit.com',
  'tiktok.com',
  'medium.com',
  'quora.com',

  // Design & Portfolios (The "Figma" Fix)
  'figma.com',
  'www.figma.com',
  'dribbble.com',
  'www.dribbble.com',
  'behance.net',
  'www.behance.net',
  'deviantart.com',
  'www.deviantart.com',
  'artstation.com',
  'www.artstation.com',
  'canva.com',
  'www.canva.com',
  'webflow.io',
  'www.webflow.io',

  // Tech News & Download Sites (False Positive Prevention)
  'cnet.com',
  'www.cnet.com',
  'download.cnet.com',
  'softpedia.com',
  'www.softpedia.com',
  'uptodown.com',
  'www.uptodown.com',
  'apkpure.com',
  'www.apkpure.com',
  'datacenterdynamics.com',
  'www.datacenterdynamics.com',
  'wikipedia.org',
  'en.wikipedia.org',
  'google.com',           // Play Store screenshots
  'play.google.com',      // Play Store
  'www.google.com'
]);

/**
 * Priority Domains Set (The "Expert Witness" List)
 * 
 * These are the TOP 50+ most-phished brands globally.
 * If ANY of these domains appear in visual search results (even just once),
 * they are IMMEDIATELY selected as the TrueDomain with artificial high confidence (1.0).
 * 
 * Reasoning: If Google Lens sees "PayPal" or "Instagram" even once in noisy results,
 * we trust it IS that brand - these are too high-profile to be random matches.
 */
const PRIORITY_DOMAINS = new Set([
  // Social Media (Extremely High Risk)
  'instagram.com',
  'facebook.com',
  'twitter.com',
  'x.com',
  'linkedin.com',
  'snapchat.com',
  'tiktok.com',
  'discord.com',
  'telegram.org',
  'whatsapp.com',
  'reddit.com',

  // Finance & Payments (Critical)
  'paypal.com',
  'stripe.com',
  'chase.com',
  'wellsfargo.com',
  'bankofamerica.com',
  'citibank.com',
  'capitalone.com',
  'americanexpress.com',
  'discover.com',
  'venmo.com',
  'cashapp.com',
  'zelle.com',

  // Crypto (High Value Targets)
  'coinbase.com',
  'binance.com',
  'kraken.com',
  'crypto.com',
  'blockchain.com',
  'metamask.io',
  'trezor.io',
  'ledger.com',
  'gemini.com',

  // Tech Giants (Credential Theft)
  'google.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'icloud.com',
  'outlook.com',
  'yahoo.com',
  'aol.com',

  // E-Commerce
  'ebay.com',
  'etsy.com',
  'shopify.com',
  'aliexpress.com',
  'alibaba.com',

  // Streaming & Entertainment
  'netflix.com',
  'spotify.com',
  'hulu.com',
  'disneyplus.com',
  'twitch.tv',
  'youtube.com',

  // Gaming (Account Theft)
  'roblox.com',
  'steam.com',
  'steampowered.com',
  'steamcommunity.com',
  'epicgames.com',
  'ea.com',
  'playstation.com',
  'xbox.com',
  'nintendo.com',

  // Cloud & Productivity
  'dropbox.com',
  'adobe.com',
  'salesforce.com',
  'docusign.com',
  'zoom.us',
  'slack.com',

  // Indian Banks (Regional High Risk)
  'sbi.co.in',
  'hdfcbank.com',
  'icicibank.com',
  'axisbank.com',
  'kotak.com',
  'paytm.com',
  'phonepe.com'
]);

/**
 * Platform Domains Set (Profile Hosts)
 * 
 * These domains host profiles/pages for OTHER brands (e.g., company LinkedIn profiles).
 * If these appear as visual match winners, we check titles to see if they're talking
 * about the current brand (not phishing the platform itself).
 * 
 * Example: Delhivery.com has a LinkedIn profile â†’ "linkedin.com" appears in results
 * â†’ We check if title contains "delhivery" â†’ If yes, it's SAFE (not phishing LinkedIn)
 */
const PLATFORM_DOMAINS = new Set([
  // Social Media & Professional Networks
  'linkedin.com',
  'facebook.com',
  'twitter.com',
  'x.com',
  'instagram.com',
  'youtube.com',
  'pinterest.com',
  'reddit.com',
  'tiktok.com',
  'snapchat.com',

  // Information & Reference
  'wikipedia.org',
  'en.wikipedia.org',

  // App Stores & Discovery
  'apple.com',
  'apps.apple.com',
  'play.google.com',
  'google.com',
  'bing.com',

  // E-Commerce (Product Pages)
  'amazon.com',
  'ebay.com',
  'etsy.com',

  // Review & Discussion Platforms
  'trustpilot.com',
  'yelp.com',
  'glassdoor.com'
]);


/**
 * Step 1: Upload screenshot to ImgBB to get a public URL
 * 
 * ImgBB API: https://api.imgbb.com/1/upload
 * Method: POST (FormData)
 * 
 * @param {string} base64Image - Base64 encoded image data URL
 * @returns {Promise<string>} - Public URL of the uploaded image
 */
async function uploadToImgBB(base64Image) {
  // Get API key
  const { imgbbKey } = await getApiKeys();

  // Extract base64 content (remove data URL prefix if present)
  let base64Content = base64Image;
  if (base64Image.includes(',')) {
    // Remove the data:image/...;base64, prefix
    base64Content = base64Image.split(',')[1];
  }

  // Create FormData for the upload
  const formData = new FormData();
  formData.append('key', imgbbKey);
  formData.append('expiration', '600'); // Auto-delete after 10 minutes (600 seconds)
  formData.append('image', base64Content); // Raw base64 string without prefix

  try {
    const response = await fetch('https://api.imgbb.com/1/upload', {
      method: 'POST',
      body: formData
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`ImgBB upload failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const data = await response.json();

    // Check for API errors in response
    if (data.error) {
      throw new Error(`ImgBB API error: ${JSON.stringify(data.error)}`);
    }

    // Return the public URL
    if (data.data && data.data.url) {
      return data.data.url;
    } else {
      throw new Error('ImgBB response missing URL');
    }

  } catch (error) {
    console.error('ImgBB upload error:', error);
    throw error;
  }
}

/**
 * Step 2: Visual Search via SerpApi (Google Lens)
 * 
 * SerpApi: https://serpapi.com/search
 * Method: GET
 * Engine: google_lens
 * 
 * @param {string} imageUrl - Public URL of the image from ImgBB
 * @returns {Promise<Array>} - Array of visual match results
 */
async function fetchVisualMatches(imageUrl) {
  // Get API key
  const { serpapiKey } = await getApiKeys();

  // Build query parameters
  const params = new URLSearchParams({
    engine: 'google_lens',
    api_key: serpapiKey,
    url: imageUrl
  });

  const apiUrl = `https://serpapi.com/search?${params.toString()}`;

  try {
    const response = await fetch(apiUrl, {
      method: 'GET'
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`SerpApi request failed: ${response.status} ${response.statusText} - ${errorText}`);
    }

    const data = await response.json();

    // Check for API errors in response
    if (data.error) {
      throw new Error(`SerpApi error: ${JSON.stringify(data.error)}`);
    }

    // Return full response object with visual matches, text results, and knowledge graph
    // This enables OCR text verification in addition to visual similarity
    return {
      visualMatches: data.visual_matches || [],
      textResults: data.text_results || [],
      knowledgeGraph: data.knowledge_graph || null
    };

  } catch (error) {
    console.error('SerpApi error:', error);
    throw error;
  }
}

/**
 * Helper: Extract Brand Keywords from OCR Text
 * 
 * Extracts potential brand names from SerpApi text_results and knowledge_graph.
 * Used for text-based phishing detection.
 * 
 * @param {Array} textResults - Array of text results from SerpApi
 * @param {Object} knowledgeGraph - Knowledge graph object from SerpApi
 * @returns {Array<string>} - Array of normalized brand keywords
 */
function extractBrandKeywords(textResults, knowledgeGraph) {
  const keywords = new Set();

  // Common stop words to filter out
  const stopWords = new Set([
    'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with',
    'login', 'sign', 'home', 'page', 'website', 'official', 'welcome', 'app',
    'www', 'http', 'https', 'com', 'org', 'net', 'secure', 'online'
  ]);

  // Extract from text_results array
  if (Array.isArray(textResults)) {
    for (const textItem of textResults) {
      // text_results can have various structures, try common fields
      const text = textItem.text || textItem.title || textItem.snippet || '';
      if (text) {
        // Split into words, normalize, filter
        const words = text.toLowerCase()
          .replace(/[^a-z0-9\s]/g, ' ')
          .split(/\s+/)
          .filter(word => word.length > 2 && !stopWords.has(word));

        words.forEach(word => keywords.add(word));
      }
    }
  }

  // Extract from knowledge_graph
  if (knowledgeGraph && typeof knowledgeGraph === 'object') {
    // Try common knowledge graph fields
    const title = knowledgeGraph.title || knowledgeGraph.name || '';
    if (title) {
      const words = title.toLowerCase()
        .replace(/[^a-z0-9\s]/g, ' ')
        .split(/\s+/)
        .filter(word => word.length > 2 && !stopWords.has(word));

      words.forEach(word => keywords.add(word));
    }
  }

  const result = Array.from(keywords);
  console.log('[DAVSS] Extracted brand keywords from OCR:', result);
  return result;
}

/**
 * Helper: Check if Brand Keywords Appear in URL
 * 
 * Checks if any extracted brand keyword appears in the current URL.
 * Used to detect text-URL mismatches (e.g., logo says "PayPal" but URL is "fake-site.com").
 * 
 * @param {Array<string>} brandKeywords - Array of brand keywords from OCR
 * @param {string} currentUrl - The current page URL
 * @returns {Object} - { found: boolean, matchedBrand: string }
 */
function checkBrandInURL(brandKeywords, currentUrl) {
  if (!brandKeywords || brandKeywords.length === 0 || !currentUrl) {
    return { found: false, matchedBrand: '' };
  }

  // Normalize URL to lowercase for comparison
  const normalizedUrl = currentUrl.toLowerCase();

  // Check each brand keyword
  for (const brand of brandKeywords) {
    if (normalizedUrl.includes(brand)) {
      console.log('[DAVSS] Brand keyword found in URL:', brand);
      return { found: true, matchedBrand: brand };
    }
  }

  console.log('[DAVSS] No brand keywords found in URL');
  return { found: false, matchedBrand: '' };
}

/**
 * Step 3: Calculate DAVSS Score
 * 
 * Analyzes visual matches to determine if the current domain matches
 * the most frequent domain in the search results.
 * NOW INCLUDES: OCR text verification to detect brand impersonation.
 * 
 * @param {Array} visualMatches - Array of visual match results from SerpApi
 * @param {string} currentDomain - Standardized current domain
 * @param {Array} textResults - Array of text results from SerpApi (for OCR)
 * @param {Object} knowledgeGraph - Knowledge graph object from SerpApi
 * @param {string} currentUrl - Full current URL (for text-URL matching)
 * @returns {Object} - Score object with similarityScore, confidenceScore, and text verification results
 */
function calculateScore(visualMatches, currentDomain, textResults = [], knowledgeGraph = null, currentUrl = '') {
  if (!visualMatches || visualMatches.length === 0) {
    return {
      similarityScore: -1,
      confidenceScore: 0,
      mostFrequentDomain: '',
      frequencyCount: 0,
      totalResults: 0,
      error: true,
      errorMessage: 'No visual matches found'
    };
  }

  // Step 1: Filter - Extract hostnames from the top 10 results
  // Split into HighValueMatches (Clean) and LowValueMatches (Noisy)
  const topResults = visualMatches.slice(0, 10);
  const cleanMatches = []; // HighValueMatches
  const noisyMatches = []; // LowValueMatches

  for (const match of topResults) {
    let domain = '';

    // Try to extract domain from 'link' field
    if (match.link) {
      try {
        const url = new URL(match.link);
        domain = url.hostname;
      } catch (error) {
        // If URL parsing fails, try string manipulation
        const matchResult = match.link.match(/https?:\/\/([^\/]+)/);
        if (matchResult) {
          domain = matchResult[1];
        }
      }
    }

    // If no domain from 'link', try 'source' field
    if (!domain && match.source) {
      try {
        const url = new URL(match.source);
        domain = url.hostname;
      } catch (error) {
        const matchResult = match.source.match(/https?:\/\/([^\/]+)/);
        if (matchResult) {
          domain = matchResult[1];
        }
      }
    }

    // Standardize domain
    if (domain) {
      const standardizedDomain = standardizeDomain(domain);

      // Separate into clean and noisy buckets
      if (NOISY_DOMAINS.has(standardizedDomain)) {
        noisyMatches.push(standardizedDomain);
      } else {
        cleanMatches.push(standardizedDomain);
      }
    }
  }

  // Debug logging
  console.log('[DAVSS] Clean Matches Found:', cleanMatches);
  console.log('[DAVSS] Noisy Matches Found:', noisyMatches);

  // Step 2: Select Winner - Initialize domainList explicitly to prevent ReferenceError
  let domainList = [];
  let analysisSource = '';

  if (cleanMatches.length > 0) {
    // Scenario A: Use clean matches (ignore noisy platforms)
    console.log('[DAVSS] Using Clean Matches (High Priority):', cleanMatches);
    domainList = cleanMatches;
    analysisSource = 'clean';
  } else if (noisyMatches.length > 0) {
    // Scenario B: Only noisy matches available (social media/design site phishing case)
    console.log('[DAVSS] Only Noisy Matches Found (Fallback):', noisyMatches);
    domainList = noisyMatches;
    analysisSource = 'noisy';
  } else {
    // No valid domains found
    return {
      similarityScore: -1,
      confidenceScore: 0,
      mostFrequentDomain: '',
      frequencyCount: 0,
      totalResults: topResults.length,
      error: true,
      errorMessage: 'No valid domains found in visual matches'
    };
  }

  // **SAFETY CHECK #1: "Anywhere Match" (False Positive Prevention)**
  // Before declaring a mismatch, check if the current brand appears ANYWHERE in the clean matches
  // Example: If we're on sbi.bank.in and "sbi.co.in" appears in result #5, it's still safe
  // This prevents false positives from tech news sites winning with low confidence
  if (cleanMatches.length > 0) {
    const currentBrand = extractBrand(extractRootDomain(currentDomain));
    console.log('[DAVSS] Safety Check: Current Brand:', currentBrand);

    // Check if current brand appears in ANY of the clean match domains
    for (const matchDomain of cleanMatches) {
      const matchBrand = extractBrand(extractRootDomain(matchDomain));
      if (matchBrand === currentBrand) {
        console.log('[DAVSS] âœ“ ANYWHERE MATCH FOUND:', matchDomain);
        console.log('[DAVSS] Current brand appears in visual results - Site is SAFE');
        return {
          similarityScore: 0,  // Safe - brand confirmed
          confidenceScore: 1.0, // Override to high confidence
          mostFrequentDomain: matchDomain,
          frequencyCount: cleanMatches.filter(d => extractBrand(extractRootDomain(d)) === currentBrand).length,
          totalResults: cleanMatches.length,
          textMatchScore: -1,
          brandKeywords: [],
          textThreatDetected: false,
          error: false,
          errorMessage: null,
          safetyOverride: 'anywhere_match' // Indicates this was caught by safety check
        };
      }
    }
    console.log('[DAVSS] No anywhere match found - proceeding with winner selection');
  }


  // Step 3: PRIORITY DOMAIN CHECK (The "Expert Witness" Override)
  // If ANY high-risk brand (Instagram, PayPal, etc.) appears in results (even once),
  // immediately select it as TrueDomain with artificial high confidence (1.0)

  let mostFrequentDomain = '';
  let maxCount = 0;
  let isPriorityMatch = false;

  // **CHECK 1: Scan for Priority Domains (High-Risk Brands)**
  console.log('[DAVSS] Scanning for priority domains (high-risk brands)...');

  for (const domain of domainList) {
    if (!domain) continue;

    // Extract root domain for comparison
    const rootDomain = extractRootDomain(domain);

    // Check if this domain is in the priority list
    if (PRIORITY_DOMAINS.has(rootDomain)) {
      console.log('[DAVSS] ðŸŽ¯ PRIORITY DOMAIN DETECTED:', rootDomain);
      console.log('[DAVSS] This is a high-risk brand - using as TrueDomain with MAX confidence');

      mostFrequentDomain = domain;
      maxCount = domainList.filter(d => extractRootDomain(d) === rootDomain).length;
      isPriorityMatch = true;
      break; // Stop searching - priority match found
    }
  }

  // **CHECK 2: Fallback to Frequency-Based Selection (Unknown Brands)**
  if (!isPriorityMatch) {
    console.log('[DAVSS] No priority domains found - using frequency-based selection');

    // Calculate frequency map for non-priority domains
    const frequencyMap = {};
    for (const domain of domainList) {
      if (domain) {
        frequencyMap[domain] = (frequencyMap[domain] || 0) + 1;
      }
    }

    // Find most frequent domain
    for (const [domain, count] of Object.entries(frequencyMap)) {
      if (count > maxCount) {
        maxCount = count;
        mostFrequentDomain = domain;
      }
    }

    console.log('[DAVSS] Selected True Domain (frequency-based):', mostFrequentDomain, `(${maxCount} matches)`);
  } else {
    console.log('[DAVSS] Selected True Domain (priority match):', mostFrequentDomain, `(${maxCount} matches)`);
  }


  // Step 4: Handle "Zero Clean Results" - Design Clone Detection
  // If domainList is mostly design sites and confidence is low, return neutral score
  const designSites = ['figma.com', 'dribbble.com', 'behance.net', 'deviantart.com',
    'artstation.com', 'canva.com', 'webflow.io'];
  const isDesignSite = designSites.some(site => mostFrequentDomain.includes(site));
  const isLowConfidence = maxCount <= 1 && domainList.length <= 2;

  if (analysisSource === 'noisy' && isDesignSite && isLowConfidence) {
    console.warn('[DAVSS] Suspected Design Clone detected. Returning neutral score.');
    return {
      similarityScore: 0.5, // Neutral score
      confidenceScore: 0.3, // Low confidence
      mostFrequentDomain: mostFrequentDomain,
      frequencyCount: maxCount,
      totalResults: domainList.length,
      error: false,
      errorMessage: null,
      warning: 'Suspected Design Clone - Results may be from design template sites'
    };
  }

  // Calculate confidence score
  let confidenceScore = maxCount / domainList.length;

  // **PRIORITY MATCH OVERRIDE**: If this is a high-risk brand, give it artificial high confidence
  // Even 1 match for Instagram/PayPal is more trustworthy than 5 matches for unknown blogs
  if (isPriorityMatch) {
    console.log('[DAVSS] Priority match detected - overriding confidence to 1.0');
    confidenceScore = 1.0; // Artificial high confidence for priority domains
  }

  // **SAFETY CHECK #2: Minimum Confidence Threshold (False Positive Prevention)**
  // If the "winner" only appears in <40% of results, the data is too weak to trust
  // Example: 1 match out of 8 results = 0.125 confidence - could be random noise
  const MIN_CONFIDENCE_THRESHOLD = 0.40;

  // NOTE: This check is SKIPPED for priority matches (already handled above with 1.0 confidence)
  if (!isPriorityMatch && confidenceScore < MIN_CONFIDENCE_THRESHOLD) {
    console.warn(`[DAVSS] âš ï¸ CONFIDENCE TOO LOW (${confidenceScore.toFixed(2)} < ${MIN_CONFIDENCE_THRESHOLD})`);
    console.warn('[DAVSS] Visual match too weak. Defaulting to SAFE to prevent false positive.');
    return {
      similarityScore: 0,  // Safe - insufficient data
      confidenceScore: confidenceScore,
      mostFrequentDomain: mostFrequentDomain,
      frequencyCount: maxCount,
      totalResults: domainList.length,
      textMatchScore: -1,
      brandKeywords: [],
      textThreatDetected: false,
      error: false,
      errorMessage: null,
      safetyOverride: 'low_confidence' // Indicates this was caught by confidence check
    };
  }

  console.log('[DAVSS] Confidence check passed:', confidenceScore.toFixed(2));

  // **STEP 5A: TITLE SAFETY CHECK (Entity Verification)**
  // Before comparing domains, check if any search result titles mention the current brand
  // This prevents false positives when LinkedIn/Facebook profiles appear in results
  // Example: "Delhivery | LinkedIn" contains "delhivery" â†’ SAFE

  const currentBrandName = extractBrandName(currentUrl);
  console.log('[DAVSS] ðŸ” Title Verification: Checking if results mention brand:', currentBrandName);

  if (currentBrandName) {
    // Scan ALL visual matches for title mentions
    for (const match of visualMatches) {
      const title = (match.title || '').toLowerCase();
      const link = (match.link || match.source || '').toLowerCase();

      // Check if title contains current brand name
      if (title && title.includes(currentBrandName)) {
        console.log('[DAVSS] âœ“ TITLE MATCH FOUND:', match.title);
        console.log('[DAVSS] Search results mention current brand - Site is SAFE');
        console.log('[DAVSS] This is likely a social media profile or news article about the brand');

        return {
          similarityScore: 0,  // Safe - brand mentioned in results
          confidenceScore: 1.0,
          mostFrequentDomain: extractRootDomain(link) || mostFrequentDomain,
          frequencyCount: maxCount,
          totalResults: domainList.length,
          textMatchScore: -1,
          brandKeywords: [],
          textThreatDetected: false,
          error: false,
          errorMessage: null,
          safetyOverride: 'title_match' // Indicates title verification triggered
        };
      }

      // Also check if link domain matches current (backup check)
      if (link && link.includes(currentDomain)) {
        console.log('[DAVSS] âœ“ DOMAIN MATCH in search results');
        return {
          similarityScore: 0,
          confidenceScore: 1.0,
          mostFrequentDomain: currentDomain,
          frequencyCount: maxCount,
          totalResults: domainList.length,
          textMatchScore: -1,
          brandKeywords: [],
          textThreatDetected: false,
          error: false,
          errorMessage: null,
          safetyOverride: 'domain_in_results'
        };
      }
    }

    console.log('[DAVSS] No title match found for brand:', currentBrandName);
  }

  // Step 5: Security-grade domain comparison using root domain and brand extraction
  // Extract root domains for both current and most frequent
  const currentRoot = extractRootDomain(currentDomain);
  const trueRoot = extractRootDomain(mostFrequentDomain);

  // Extract brand names for brand-based comparison (allows cross-TLD matches)
  const brandCurrent = extractBrand(currentRoot);
  const brandTrue = extractBrand(trueRoot);

  // Extract TLD from current domain for whitelist checking
  const currentTLD = extractTLD(currentRoot);

  console.log('[DAVSS] Current Root Domain:', currentRoot, '| Brand:', brandCurrent, '| TLD:', currentTLD);
  console.log('[DAVSS] True Root Domain:', trueRoot, '| Brand:', brandTrue);

  // **STEP 5B: PLATFORM FILTER (LinkedIn/Facebook Profile Detection)**
  // If the visual winner is a "platform" domain (LinkedIn, Facebook, etc.),
  // check if current site is mimicking the platform login, or just has a profile there

  const isPlatformWinner = PLATFORM_DOMAINS.has(trueRoot);

  if (isPlatformWinner) {
    console.log('[DAVSS] ðŸŒ Winner is a PLATFORM domain:', trueRoot);
    console.log('[DAVSS] Checking if current site mimics platform or just has a profile...');

    // Extract clean brand names for comparison
    const platformBrand = extractBrand(trueRoot); // e.g., "linkedin"

    // Check if current domain is trying to mimic the platform
    // e.g., "linkedln-login.com" or "secure-linkedin.com"
    if (currentBrandName.includes(platformBrand)) {
      // Current brand name contains platform name - likely phishing the platform itself
      console.warn('[DAVSS] âš ï¸ PLATFORM LOGIN MIMIC DETECTED!');
      console.warn(`[DAVSS] Current site "${currentBrandName}" appears to mimic ${platformBrand}`);
      // Don't return here - let it fall through to scoring logic
    } else {
      // Current brand does NOT contain platform name
      // This is likely a company's social media profile, not phishing
      // Example: delhivery.com has a LinkedIn profile
      console.log('[DAVSS] âœ“ PLATFORM PROFILE DETECTED (NOT phishing)');
      console.log(`[DAVSS] Current brand "${currentBrandName}" is different from platform "${platformBrand}"`);
      console.log('[DAVSS] This appears to be a legitimate business with a social media profile');

      return {
        similarityScore: 0,  // Safe - platform profile
        confidenceScore: 1.0,
        mostFrequentDomain: mostFrequentDomain,
        frequencyCount: maxCount,
        totalResults: domainList.length,
        textMatchScore: -1,
        brandKeywords: [],
        textThreatDetected: false,
        error: false,
        errorMessage: null,
        safetyOverride: 'platform_profile' // Indicates platform filter triggered
      };
    }
  }

  // Strict comparison: Check if brands match
  // This allows amazon.co.uk to match amazon.com (same brand, different TLD)
  const brandsMatch = brandCurrent === brandTrue;

  // **NEW DETECTION-BASED SCORING LOGIC**
  // Instead of percentage-based scores, use a high baseline for any domain mismatch
  let similarityScore;

  if (brandsMatch) {
    // Brands match - now check if TLD is safe
    if (SAFE_TLDS.has(currentTLD)) {
      // Brand matches AND TLD is in safe list -> Safe
      similarityScore = 0;
      console.log('[DAVSS] Brand match with safe TLD:', currentTLD);
    } else {
      // Brand matches BUT TLD is NOT in safe list -> Suspicious
      similarityScore = 0.75;
      console.warn(`[DAVSS] Suspicious TLD detected: .${currentTLD} for brand ${brandCurrent}`);
    }
  } else {
    // Brands don't match -> HIGH THREAT (Detection-Based Scoring)
    // Base threat score: 0.85 (high baseline for any visual mismatch)
    // Confidence bonus: up to +0.15 based on frequency
    // Result: Even 2/8 match (0.25 confidence) = 0.85 + (0.25 * 0.15) = ~0.89
    similarityScore = 0.85 + (confidenceScore * 0.15);
    console.warn('[DAVSS] Brand mismatch detected (HIGH THREAT):', {
      current: brandCurrent,
      true: brandTrue,
      confidenceScore: confidenceScore,
      similarityScore: similarityScore
    });
  }

  // Step 6: OCR Text Verification (Override for Low Visual Confidence)
  // Extract brand keywords from logo text and check if they appear in the current URL
  const brandKeywords = extractBrandKeywords(textResults, knowledgeGraph);
  const urlCheck = checkBrandInURL(brandKeywords, currentUrl);

  let textThreatDetected = false;
  let textMatchScore = -1; // -1 = inconclusive (no text detected)

  if (brandKeywords.length > 0) {
    if (!urlCheck.found) {
      // CRITICAL: Logo text says "Chase" but URL doesn't contain "chase"
      // This is a strong indicator of brand impersonation
      textThreatDetected = true;
      textMatchScore = 0; // Text mismatch detected
      console.error('[DAVSS] TEXT MISMATCH DETECTED (BRAND IMPERSONATION):', {
        logoText: brandKeywords,
        url: currentUrl,
        textMatchScore: textMatchScore
      });
    } else {
      // Logo text matches URL - good sign
      textMatchScore = 1.0; // Text match confirmed
      console.log('[DAVSS] Text verification passed:', urlCheck.matchedBrand);
    }
  } else {
    console.log('[DAVSS] No brand text detected in logo - text verification inconclusive');
  }

  // **OVERRIDE LOGIC**: If visual confidence is low BUT text threat is detected
  // This catches cases where visual matches are weak/noisy but logo text clearly shows different brand
  if (confidenceScore < 0.5 && textThreatDetected) {
    console.warn('[DAVSS] âš ï¸ OVERRIDING visual score with text-based detection');
    console.warn('[DAVSS] Logo contains brand text that does NOT match URL - HIGH THREAT');
    similarityScore = 0.95; // Critical phishing - text contradiction overrides weak visual data
  }

  return {
    similarityScore,
    confidenceScore,
    mostFrequentDomain,
    frequencyCount: maxCount,
    totalResults: domainList.length,
    textMatchScore,        // NEW: -1 = no text, 0 = mismatch, 1.0 = match
    brandKeywords,         // NEW: Array of brand names found in logo text
    textThreatDetected,    // NEW: Boolean - true if logo text doesn't match URL
    error: false,
    errorMessage: null
  };
}

/**
 * Main DAVSS calculation function
 * 
 * Orchestrates the entire DAVSS workflow:
 * 1. Captures screenshot of current tab
 * 2. Uploads to ImgBB to get public URL
 * 3. Searches via SerpApi (Google Lens)
 * 4. Calculates similarity score
 * 
 * @param {number} tabId - The ID of the current tab to capture
 * @param {string} currentUrl - The URL of the current page
 * @returns {Promise<Object>} - Promise resolving to score object:
 *   {
 *     similarityScore: number,  // 0 = legitimate, >0 = impersonation detected
 *     confidenceScore: number,   // Frequency of most common domain
 *     currentDomain: string,     // Standardized current domain
 *     trueDomain: string,        // Most frequent domain from visual search
 *     frequencyCount: number,    // Count of most frequent domain
 *     totalResults: number,      // Total results analyzed
 *     error: boolean,            // Whether an error occurred
 *     errorMessage: string      // Error message if error occurred
 *   }
 */
export async function calculateDavssScore(tabId, currentUrl) {
  try {
    // Step 1: Image Capture
    // Capture the visible tab as a base64 data URL
    let imageROI;
    let logoCrop = null;
    try {
      // Get the window ID from the tab
      let windowId = null;
      if (tabId) {
        try {
          const tab = await chrome.tabs.get(tabId);
          windowId = tab.windowId;
        } catch (tabError) {
          console.warn('Could not get window ID from tab, using null:', tabError);
        }
      }

      // Capture visible tab (null windowId means current window)
      imageROI = await new Promise((resolve, reject) => {
        chrome.tabs.captureVisibleTab(windowId, {
          format: 'png',
          quality: 100
        }, (dataUrl) => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
          } else {
            resolve(dataUrl);
          }
        });
      });

      // Attempt logo detection and crop
      const logoInfo = await getLogoCoordinates(tabId);
      if (logoInfo && logoInfo.rect) {
        try {
          logoCrop = await cropImageToRect(imageROI, logoInfo.rect, logoInfo.dpr);
          console.log('[DAVSS] Logo crop succeeded');
        } catch (cropErr) {
          console.warn('[DAVSS] Logo crop failed, falling back to full screenshot:', cropErr);
          logoCrop = null;
        }
      } else {
        console.log('[DAVSS] No logo detected; using full screenshot');
      }
    } catch (captureError) {
      return {
        similarityScore: -1,
        confidenceScore: 0,
        currentDomain: '',
        trueDomain: '',
        frequencyCount: 0,
        totalResults: 0,
        error: true,
        errorMessage: `Failed to capture screenshot: ${captureError.message}`
      };
    }

    // Step 2: Upload to ImgBB
    let imageUrl;
    try {
      const imageToUse = logoCrop || imageROI;
      imageUrl = await uploadToImgBB(imageToUse);
      console.log('[DAVSS] Image uploaded to ImgBB:', imageUrl);
    } catch (uploadError) {
      return {
        similarityScore: -1,
        confidenceScore: 0,
        currentDomain: '',
        trueDomain: '',
        frequencyCount: 0,
        totalResults: 0,
        error: true,
        errorMessage: `Failed to upload image to ImgBB: ${uploadError.message}`
      };
    }

    // Step 3: Visual Search via SerpApi (with OCR Text Extraction)
    let visualMatches, textResults, knowledgeGraph;
    try {
      const serpApiResponse = await fetchVisualMatches(imageUrl);
      visualMatches = serpApiResponse.visualMatches;
      textResults = serpApiResponse.textResults;
      knowledgeGraph = serpApiResponse.knowledgeGraph;

      console.log('[DAVSS] Visual matches found:', visualMatches.length);
      console.log('[DAVSS] Text results found:', textResults.length);
      console.log('[DAVSS] Knowledge graph available:', !!knowledgeGraph);

      if (!visualMatches || visualMatches.length === 0) {
        return {
          similarityScore: -1,
          confidenceScore: 0,
          currentDomain: '',
          trueDomain: '',
          frequencyCount: 0,
          totalResults: 0,
          error: true,
          errorMessage: 'SerpApi returned no visual matches'
        };
      }
    } catch (searchError) {
      return {
        similarityScore: -1,
        confidenceScore: 0,
        currentDomain: '',
        trueDomain: '',
        frequencyCount: 0,
        totalResults: 0,
        error: true,
        errorMessage: `SerpApi search failed: ${searchError.message}`
      };
    }

    // ==================================================================
    // WEIGHTED EVIDENCE PIPELINE - VERDICT ENGINE
    // ==================================================================

    console.log('[DAVSS] â•â•â• WEIGHTED EVIDENCE PIPELINE â•â•â•');

    // STEP 1: Parse Current URL
    const currentDetails = parseUrlDetails(currentUrl);
    if (!currentDetails.isValid) {
      return {
        similarityScore: -1,
        confidenceScore: 0,
        currentDomain: '',
        trueDomain: '',
        status: 'Error: Invalid URL',
        error: true,
        errorMessage: 'Failed to parse current URL'
      };
    }

    console.log('[DAVSS] Current URL Details:', currentDetails);

    // STEP 2: Extract Signals
    const signals = extractSignals(visualMatches, currentDetails);

    // STEP 3: VERDICT ENGINE - Evaluate signals against scenarios
    console.log('[DAVSS] â•â•â• EVALUATING VERDICT â•â•â•');

    // SCENARIO A: Direct Validation
    if (signals.visualDomainMatch) {
      console.log('[DAVSS] âœ“ SCENARIO A: Direct Validation');
      return {
        similarityScore: 0,
        confidenceScore: 1.0,
        currentDomain: currentDetails.hostname,
        trueDomain: currentDetails.hostname,
        status: 'Safe: Visual Match Confirmed',
        scenario: 'A',
        error: false
      };
    }

    // SCENARIO B: Contextual Validation
    if (signals.titleKeywordMatch && CONFIG.SAFE_TLDS.has(currentDetails.tld)) {
      console.log('[DAVSS] âœ“ SCENARIO B: Contextual Validation');
      return {
        similarityScore: 0,
        confidenceScore: 0.9,
        currentDomain: currentDetails.hostname,
        trueDomain: currentDetails.hostname,
        status: 'Safe: Verified Entity on Safe TLD',
        scenario: 'B',
        error: false
      };
    }

    // SCENARIO C: TLD Trap
    if (signals.titleKeywordMatch && CONFIG.RISKY_TLDS.has(currentDetails.tld)) {
      console.warn('[DAVSS] âš ï¸ SCENARIO C: TLD Trap');
      return {
        similarityScore: 0.85,
        confidenceScore: 0.8,
        currentDomain: currentDetails.hostname,
        trueDomain: signals.detectedTrueDomain || 'Unknown',
        status: 'Phishing: Brand Match on Risky TLD',
        scenario: 'C',
        error: false
      };
    }

    // SCENARIO D: Priority Impersonation
    if (signals.foundPriorityBrand && signals.detectedTrueDomain !== currentDetails.hostname) {
      console.warn('[DAVSS] âš ï¸ SCENARIO D: Priority Impersonation');
      return {
        similarityScore: 0.95,
        confidenceScore: 1.0,
        currentDomain: currentDetails.hostname,
        trueDomain: signals.detectedTrueDomain,
        status: `Phishing: ${signals.priorityBrandName.toUpperCase()} Impersonation`,
        scenario: 'D',
        error: false
      };
    }

    // SCENARIO E: Inconclusive
    console.log('[DAVSS] â“ SCENARIO E: Inconclusive');
    const verdictResult = {
      similarityScore: 0,
      confidenceScore: 0,
      currentDomain: currentDetails.hostname,
      trueDomain: null,
      status: 'Inconclusive: Insufficient Data',
      scenario: 'E',
      error: false
    };

    // Return verdict
    return verdictResult;

  } catch (error) {
    // Catch any unexpected errors
    console.error('[DAVSS] Unexpected error:', error);
    return {
      similarityScore: -1,
      confidenceScore: 0,
      currentDomain: '',
      trueDomain: '',
      frequencyCount: 0,
      totalResults: 0,
      error: true,
      errorMessage: `Unexpected error: ${error.message}`
    };
  }
}