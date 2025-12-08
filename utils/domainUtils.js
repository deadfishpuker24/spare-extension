/**
 * Domain Utilities
 * 
 * Helper functions for domain parsing and whitelist checking.
 */

import { TRUSTED_DOMAINS } from '../data/trustedList.js';

/**
 * Known two-part TLDs (e.g., .co.uk, .com.au)
 * These require special handling when extracting root domains.
 */
const TWO_PART_TLDS = new Set([
  'co.uk', 'com.au', 'co.nz', 'co.za', 'com.br', 'com.mx',
  'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.ec', 'com.uy',
  'com.py', 'com.bo', 'com.cl', 'com.cr', 'com.gt', 'com.hn',
  'com.ni', 'com.pa', 'com.sv', 'com.do', 'com.pr', 'com.cu',
  'gov.uk', 'org.uk', 'ac.uk', 'net.au', 'org.au', 'edu.au',
  'gov.au', 'net.nz', 'org.nz', 'ac.nz', 'co.jp', 'ne.jp',
  'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'ac.kr',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'com.tw',
  'org.tw', 'edu.tw', 'gov.tw', 'com.hk', 'org.hk', 'edu.hk',
  'gov.hk', 'com.sg', 'org.sg', 'edu.sg', 'gov.sg', 'com.my',
  'org.my', 'edu.my', 'gov.my', 'com.ph', 'org.ph', 'edu.ph',
  'gov.ph', 'com.id', 'org.id', 'edu.id', 'gov.id', 'com.th',
  'org.th', 'edu.th', 'gov.th', 'com.vn', 'org.vn', 'edu.vn',
  'gov.vn'
]);

/**
 * Extracts the root domain from a URL or hostname
 * 
 * Examples:
 * - secure.pay.amazon.com -> amazon.com
 * - www.google.co.uk -> google.co.uk
 * - subdomain.example.com -> example.com
 * 
 * @param {string} urlOrHostname - Full URL or hostname string
 * @returns {string} - Root domain (e.g., "amazon.com" or "google.co.uk")
 */
function extractRootDomain(urlOrHostname) {
  if (!urlOrHostname) return '';
  
  let hostname = '';
  
  try {
    // If it's a full URL, parse it
    if (urlOrHostname.startsWith('http://') || urlOrHostname.startsWith('https://')) {
      const url = new URL(urlOrHostname);
      hostname = url.hostname;
    } else {
      // Assume it's already a hostname
      hostname = urlOrHostname;
    }
  } catch (error) {
    // If URL parsing fails, try to extract hostname manually
    const match = urlOrHostname.match(/https?:\/\/([^\/]+)/);
    if (match) {
      hostname = match[1];
    } else {
      hostname = urlOrHostname;
    }
  }
  
  // Remove www. prefix (case-insensitive)
  hostname = hostname.replace(/^www\./i, '');
  
  // Split into parts
  const parts = hostname.toLowerCase().split('.');
  
  if (parts.length < 2) {
    return hostname.toLowerCase();
  }
  
  // Check if the last two parts form a known two-part TLD
  const lastTwoParts = parts.slice(-2).join('.');
  if (TWO_PART_TLDS.has(lastTwoParts)) {
    // For two-part TLDs, we need the last 3 parts (domain.co.uk)
    if (parts.length >= 3) {
      return parts.slice(-3).join('.');
    } else {
      return hostname.toLowerCase();
    }
  } else {
    // Standard case: take the last 2 parts (domain.tld)
    return parts.slice(-2).join('.');
  }
}

/**
 * Checks if a domain is whitelisted (trusted)
 * 
 * This function:
 * 1. Parses the URL to extract the hostname
 * 2. Extracts the root domain (handling subdomains and multi-part TLDs)
 * 3. Checks if the root domain exists in the TRUSTED_DOMAINS Set
 * 
 * @param {string} url - The URL to check
 * @returns {boolean} - True if the domain is whitelisted, false otherwise
 */
export function isDomainWhitelisted(url) {
  if (!url) return false;
  
  try {
    const rootDomain = extractRootDomain(url);
    return TRUSTED_DOMAINS.has(rootDomain);
  } catch (error) {
    console.error('[DomainUtils] Error checking whitelist:', error);
    return false; // On error, assume not whitelisted (fail secure)
  }
}

/**
 * Gets the root domain from a URL (for logging/debugging)
 * 
 * @param {string} url - The URL to extract root domain from
 * @returns {string} - The root domain
 */
export function getRootDomain(url) {
  return extractRootDomain(url);
}

