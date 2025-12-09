/**
 * Trusted Domains Whitelist
 * 
 * This Set contains the root domains of trusted, legitimate websites.
 * Domains in this list will bypass all security scans to improve performance.
 * 
 * Using a Set for O(1) lookup performance.
 */

export const TRUSTED_DOMAINS = new Set([
  // Tech/Search
  'google.com',
  'microsoft.com',
  'apple.com',
  'github.com',
  'stackoverflow.com',
  'bing.com',
  'yahoo.com',
  
  // Social
  'facebook.com',
  'instagram.com',
  'twitter.com',
  'x.com',
  'linkedin.com',
  'pinterest.com',
  'reddit.com',
  'youtube.com',
  'tiktok.com',
  'whatsapp.com',
  
  // E-Commerce
  'amazon.com',
  'ebay.com',
  'walmart.com',
  'bestbuy.com',
  'target.com',
  'etsy.com',
  'flipkart.com',
  'aliexpress.com',
  
  // Finance/Payments
  'paypal.com',
  'stripe.com',
  'chase.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'americanexpress.com',
  'wise.com',
  'hdfc.bank.in',
  
  // Services
  'netflix.com',
  'spotify.com',
  'twitch.tv',
  'zoom.us',
  'dropbox.com',
  'adobe.com',
  'salesforce.com',
  'intuit.com'
]);

