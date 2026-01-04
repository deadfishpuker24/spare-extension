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
 * - https://www.delhivery.com → "delhivery"
 * - https://secure.login.microsoft.com → "microsoft"
 * - https://free-robux-scam.com → "free-robux-scam"
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
 * Example: Delhivery.com has a LinkedIn profile → "linkedin.com" appears in results
 * → We check if title contains "delhivery" → If yes, it's SAFE (not phishing LinkedIn)
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
      trueDomain: null, // N/A
      frequencyCount: 0,
      totalResults: 0,
      error: true,
      errorMessage: 'No visual matches found'
    };
  }

  // Step 1: Filter - Split into clean and noisy matches
  const topResults = visualMatches.slice(0, 10);
  const cleanMatches = [];
  const noisyMatches = [];

  for (const match of topResults) {
    let domain = '';
    
    if (match.link) {
      try {
        const url = new URL(match.link);
        domain = url.hostname;
      } catch (error) {
        const matchResult = match.link.match(/https?:\/\/([^\/]+)/);
        if (matchResult) domain = matchResult[1];
      }
    }
    
    if (!domain && match.source) {
      try {
        const url = new URL(match.source);
        domain = url.hostname;
      } catch (error) {
        const matchResult = match.source.match(/https?:\/\/([^\/]+)/);
        if (matchResult) domain = matchResult[1];
      }
    }
    
    if (domain) {
      const standardizedDomain = standardizeDomain(domain);
      if (NOISY_DOMAINS.has(standardizedDomain)) {
        noisyMatches.push({
          domain: standardizedDomain,
          title: match.title || '',
          link: match.link || match.source || ''
        });
      } else {
        cleanMatches.push({
          domain: standardizedDomain,
          title: match.title || '',
          link: match.link || match.source || ''
        });
      }
    }
  }

  console.log('[DAVSS] Clean Matches:', cleanMatches.length);
  console.log('[DAVSS] Noisy Matches:', noisyMatches.length);

  // **FIX #1: If ZERO clean matches, return N/A instead of using noisy domains**
  if (cleanMatches.length === 0) {
    console.warn('[DAVSS] ❌ NO CLEAN MATCHES FOUND - Only noisy domains detected');
    console.warn('[DAVSS] Noisy domains found:', noisyMatches.map(m => m.domain));
    
    // Check if noisy matches mention current brand in titles (company profiles case)
    const currentBrandName = extractBrandName(currentUrl);
    if (currentBrandName && noisyMatches.length > 0) {
      // Use fuzzy matching for brand in title
      const brandMentioned = noisyMatches.some(match => 
        fuzzyBrandMatch(match.title, currentBrandName)
      );
      
      if (brandMentioned) {
        console.log('[DAVSS] ✓ SOCIAL PROFILE DETECTED - Brand mentioned in noisy results');
        return {
          similarityScore: 0,
          confidenceScore: 1.0,
          mostFrequentDomain: noisyMatches[0].domain,
          trueDomain: noisyMatches[0].domain,
          frequencyCount: noisyMatches.length,
          totalResults: noisyMatches.length,
          textMatchScore: -1,
          brandKeywords: [],
          textThreatDetected: false,
          error: false,
          errorMessage: null,
          safetyOverride: 'social_profile'
        };
      }
    }
    
    // Otherwise return N/A
    return {
      similarityScore: -1,
      confidenceScore: 0,
      mostFrequentDomain: noisyMatches.length > 0 ? noisyMatches[0].domain : '',
      trueDomain: null, // **N/A - Visual analysis inconclusive**
      frequencyCount: 0,
      totalResults: topResults.length,
      textMatchScore: -1,
      brandKeywords: [],
      textThreatDetected: false,
      error: false,
      errorMessage: null,
      warning: 'Only noisy domains found (social media/design sites) - Cannot determine true domain'
    };
  }

  // Step 2: Use ONLY clean matches for analysis
  const domainList = cleanMatches.map(m => m.domain);
  console.log('[DAVSS] Using Clean Matches:', domainList);

  // **SAFETY CHECK #1: "Anywhere Match" - Check if current brand appears in ANY clean match**
  const currentBrand = extractBrand(extractRootDomain(currentDomain));
  console.log('[DAVSS] 🔍 Current Brand:', currentBrand);

  for (const match of cleanMatches) {
    const matchBrand = extractBrand(extractRootDomain(match.domain));
    if (matchBrand === currentBrand) {
      console.log('[DAVSS] ✓ ANYWHERE MATCH FOUND:', match.domain);
      return {
        similarityScore: 0,
        confidenceScore: 1.0,
        mostFrequentDomain: match.domain,
        trueDomain: match.domain,
        frequencyCount: cleanMatches.filter(m => extractBrand(extractRootDomain(m.domain)) === currentBrand).length,
        totalResults: cleanMatches.length,
        textMatchScore: -1,
        brandKeywords: [],
        textThreatDetected: false,
        error: false,
        errorMessage: null,
        safetyOverride: 'anywhere_match'
      };
    }
  }

  // **SAFETY CHECK #2: Title Verification with Fuzzy Matching**
  const currentBrandName = extractBrandName(currentUrl);
  if (currentBrandName) {
    for (const match of cleanMatches) {
      if (fuzzyBrandMatch(match.title, currentBrandName)) {
        console.log('[DAVSS] ✓ FUZZY TITLE MATCH:', match.title);
        return {
          similarityScore: 0,
          confidenceScore: 1.0,
          mostFrequentDomain: match.domain,
          trueDomain: match.domain,
          frequencyCount: cleanMatches.length,
          totalResults: cleanMatches.length,
          textMatchScore: -1,
          brandKeywords: [],
          textThreatDetected: false,
          error: false,
          errorMessage: null,
          safetyOverride: 'title_match'
        };
      }
    }
  }

  // Step 3: Priority Domain Check
  let mostFrequentDomain = '';
  let maxCount = 0;
  let isPriorityMatch = false;

  for (const match of cleanMatches) {
    const rootDomain = extractRootDomain(match.domain);
    if (PRIORITY_DOMAINS.has(rootDomain)) {
      console.log('[DAVSS] 🎯 PRIORITY DOMAIN:', rootDomain);
      mostFrequentDomain = match.domain;
      maxCount = cleanMatches.filter(m => extractRootDomain(m.domain) === rootDomain).length;
      isPriorityMatch = true;
      break;
    }
  }

  // Step 4: Frequency-Based Selection (if no priority match)
  if (!isPriorityMatch) {
    const frequencyMap = {};
    for (const match of cleanMatches) {
      frequencyMap[match.domain] = (frequencyMap[match.domain] || 0) + 1;
    }
    
    for (const [domain, count] of Object.entries(frequencyMap)) {
      if (count > maxCount) {
        maxCount = count;
        mostFrequentDomain = domain;
      }
    }
  }

  // **FIX #3: Better Confidence Threshold Logic**
  let confidenceScore = maxCount / cleanMatches.length;
  
  if (isPriorityMatch) {
    confidenceScore = 1.0; // Override for priority brands
  }

  const MIN_CONFIDENCE_THRESHOLD = 0.30; // Lowered from 0.40
  
  // **NEW LOGIC: Only return N/A if confidence is LOW AND it's not a priority match**
  if (!isPriorityMatch && confidenceScore < MIN_CONFIDENCE_THRESHOLD) {
    console.warn(`[DAVSS] ⚠️ CONFIDENCE TOO LOW (${confidenceScore.toFixed(2)})`);
    console.warn('[DAVSS] Insufficient data - returning N/A');
    return {
      similarityScore: -1,
      confidenceScore: confidenceScore,
      mostFrequentDomain: mostFrequentDomain,
      trueDomain: null, // **N/A - Confidence too low**
      frequencyCount: maxCount,
      totalResults: cleanMatches.length,
      textMatchScore: -1,
      brandKeywords: [],
      textThreatDetected: false,
      error: false,
      errorMessage: null,
      safetyOverride: 'low_confidence'
    };
  }

  // Step 5: Domain Comparison
  const currentRoot = extractRootDomain(currentDomain);
  const trueRoot = extractRootDomain(mostFrequentDomain);
  const brandCurrent = extractBrand(currentRoot);
  const brandTrue = extractBrand(trueRoot);
  const currentTLD = extractTLD(currentRoot);

  console.log('[DAVSS] Current:', currentRoot, '| Brand:', brandCurrent);
  console.log('[DAVSS] True:', trueRoot, '| Brand:', brandTrue);

  const brandsMatch = brandCurrent === brandTrue;
  let similarityScore;

  if (brandsMatch) {
    if (SAFE_TLDS.has(currentTLD)) {
      similarityScore = 0; // Safe
    } else {
      similarityScore = 0.75; // Suspicious TLD
    }
  } else {
    similarityScore = 0.85 + (confidenceScore * 0.15); // High threat
  }

  // Step 6: OCR Text Verification
  const brandKeywords = extractBrandKeywords(textResults, knowledgeGraph);
  const urlCheck = checkBrandInURL(brandKeywords, currentUrl);
  
  let textThreatDetected = false;
  let textMatchScore = -1;
  
  if (brandKeywords.length > 0) {
    textMatchScore = urlCheck.found ? 1.0 : 0;
    textThreatDetected = !urlCheck.found;
    
    if (confidenceScore < 0.5 && textThreatDetected) {
      console.warn('[DAVSS] ⚠️ TEXT OVERRIDE - Logo brand mismatch detected');
      similarityScore = 0.95;
    }
  }

  return {
    similarityScore,
    confidenceScore,
    mostFrequentDomain,
    trueDomain: mostFrequentDomain, // **Valid trueDomain found**
    frequencyCount: maxCount,
    totalResults: cleanMatches.length,
    textMatchScore,
    brandKeywords,
    textThreatDetected,
    error: false,
    errorMessage: null
  };
}

/**
 * **NEW HELPER: Fuzzy Brand Matching**
 * 
 * More robust than exact substring matching.
 * Handles case variations, word boundaries, and common separators.
 */
function fuzzyBrandMatch(text, brandName) {
  if (!text || !brandName) return false;
  
  const normalizedText = text.toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ') // Remove special chars
    .replace(/\s+/g, ' ') // Normalize spaces
    .trim();
  
  const normalizedBrand = brandName.toLowerCase()
    .replace(/[^a-z0-9]/g, ''); // Remove all non-alphanumeric
  
  // Check for word boundary match (more precise)
  const words = normalizedText.split(' ');
  return words.some(word => 
    word.replace(/[^a-z0-9]/g, '') === normalizedBrand
  );
}

/**
 * Helper: Generate human-readable status message
 */
function generateStatus(scoreResult) {
  if (scoreResult.error) {
    return 'Error: ' + (scoreResult.errorMessage || 'Unknown error');
  }
  
  if (scoreResult.warning) {
    return 'Warning: ' + scoreResult.warning;
  }
  
  if (!scoreResult.trueDomain || scoreResult.trueDomain === null) {
    return 'Inconclusive - Visual Analysis N/A';
  }
  
  if (scoreResult.similarityScore === 0) {
    return 'Safe: Visual Match Confirmed';
  }
  
  if (scoreResult.similarityScore >= 0.85) {
    return 'High Risk: Domain Mismatch Detected';
  }
  
  if (scoreResult.similarityScore >= 0.70) {
    return 'Medium Risk: Suspicious Indicators';
  }
  
  return 'Low Risk: Minor Anomalies Detected';
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
 * @returns {Promise<Object>} - Promise resolving to score object
 */
export async function calculateDavssScore(tabId, currentUrl) {
  try {
    // Step 1: Image Capture
    let imageROI;
    let logoCrop = null;
    try {
      let windowId = null;
      if (tabId) {
        try {
          const tab = await chrome.tabs.get(tabId);
          windowId = tab.windowId;
        } catch (tabError) {
          console.warn('Could not get window ID from tab, using null:', tabError);
        }
      }

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
        trueDomain: null,
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
        trueDomain: null,
        frequencyCount: 0,
        totalResults: 0,
        error: true,
        errorMessage: `Failed to upload image to ImgBB: ${uploadError.message}`
      };
    }

    // Step 3: Visual Search via SerpApi
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
          trueDomain: null,
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
        trueDomain: null,
        frequencyCount: 0,
        totalResults: 0,
        error: true,
        errorMessage: `SerpApi search failed: ${searchError.message}`
      };
    }

    // Step 4: Calculate Score using the FIXED calculateScore function
    const standardizedDomain = standardizeDomain(currentUrl);
    console.log('[DAVSS] Standardized current domain:', standardizedDomain);
    
    const scoreResult = calculateScore(
      visualMatches,
      standardizedDomain,
      textResults,
      knowledgeGraph,
      currentUrl
    );

    console.log('[DAVSS] Score Result:', scoreResult);

    // Step 5: Format and return result
    return {
      similarityScore: scoreResult.similarityScore,
      confidenceScore: scoreResult.confidenceScore,
      currentDomain: standardizedDomain,
      trueDomain: scoreResult.trueDomain, // Can be null (N/A) or a valid domain
      mostFrequentDomain: scoreResult.mostFrequentDomain,
      frequencyCount: scoreResult.frequencyCount,
      totalResults: scoreResult.totalResults,
      textMatchScore: scoreResult.textMatchScore,
      brandKeywords: scoreResult.brandKeywords,
      textThreatDetected: scoreResult.textThreatDetected,
      error: scoreResult.error,
      errorMessage: scoreResult.errorMessage,
      safetyOverride: scoreResult.safetyOverride,
      warning: scoreResult.warning,
      whitelisted: false, // Domain whitelist check happens in background.js
      status: scoreResult.safetyOverride || generateStatus(scoreResult)
    };

  } catch (error) {
    console.error('[DAVSS] Unexpected error:', error);
    return {
      similarityScore: -1,
      confidenceScore: 0,
      currentDomain: '',
      trueDomain: null,
      frequencyCount: 0,
      totalResults: 0,
      error: true,
      errorMessage: `Unexpected error: ${error.message}`
    };
  }
}
