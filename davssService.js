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
const SERPAPI_KEY = '081207b3c5172c4c497812a945b99718c9aebe553d19b09085ece1884dd5e9df';

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
  'edu', 'gov', 'mil', 'int','io', 'ai', 'co', 'me', 'app', 'dev',
  
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
 * These are social media, content platforms, and design/portfolio sites that frequently 
 * appear in visual search results (e.g., YouTube videos of product reviews, Figma templates, 
 * etc.) but are not the actual brand domain being scanned. We filter these out unless 
 * they are the ONLY results.
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
  'www.webflow.io'
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
    
    // Return the visual_matches array
    if (data.visual_matches && Array.isArray(data.visual_matches)) {
      return data.visual_matches;
    } else {
      // If no visual_matches, return empty array
      console.warn('SerpApi returned no visual_matches');
      return [];
    }
    
  } catch (error) {
    console.error('SerpApi error:', error);
    throw error;
  }
}

/**
 * Step 3: Calculate DAVSS Score
 * 
 * Analyzes visual matches to determine if the current domain matches
 * the most frequent domain in the search results.
 * 
 * @param {Array} visualMatches - Array of visual match results from SerpApi
 * @param {string} currentDomain - Standardized current domain
 * @returns {Object} - Score object with similarityScore and confidenceScore
 */
function calculateScore(visualMatches, currentDomain) {
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
  
  // Step 3: Calculate - Find the most frequent domain from the selected list
  const frequencyMap = {};
  for (const domain of domainList) {
    if (domain) {
      frequencyMap[domain] = (frequencyMap[domain] || 0) + 1;
    }
  }
  
  let mostFrequentDomain = '';
  let maxCount = 0;
  
  for (const [domain, count] of Object.entries(frequencyMap)) {
    if (count > maxCount) {
      maxCount = count;
      mostFrequentDomain = domain;
    }
  }
  
  // Debug logging
  console.log('[DAVSS] Selected True Domain:', mostFrequentDomain, `(from ${analysisSource} matches)`);
  
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
  const confidenceScore = maxCount / domainList.length;
  
  // Step 5: Security-grade domain comparison using root domain and brand extraction
  // Extract root domains for both current and most frequent
  const currentRoot = extractRootDomain(currentDomain);
  const trueRoot = extractRootDomain(mostFrequentDomain);
  
  // Extract brand names for brand-based comparison (allows cross-TLD matches)
  const brandCurrent = extractBrand(currentRoot);
  const brandTrue = extractBrand(trueRoot);
  
  // Extract TLD from current domain for whitelist checking
  const currentTLD = extractTLD(currentRoot);
  
  // Debug logging
  console.log('[DAVSS] Current Root Domain:', currentRoot, '| Brand:', brandCurrent, '| TLD:', currentTLD);
  console.log('[DAVSS] True Root Domain:', trueRoot, '| Brand:', brandTrue);
  
  // Strict comparison: Check if brands match
  // This allows amazon.co.uk to match amazon.com (same brand, different TLD)
  const brandsMatch = brandCurrent === brandTrue;
  
  // Calculate similarity score with TLD whitelist check
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
    // Brands don't match -> Potential Phishing
    similarityScore = confidenceScore;
    console.warn('[DAVSS] Brand mismatch detected:', {
      current: brandCurrent,
      true: brandTrue,
      similarityScore: similarityScore
    });
  }
  
  return {
    similarityScore,
    confidenceScore,
    mostFrequentDomain,
    frequencyCount: maxCount,
    totalResults: domainList.length,
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
      imageUrl = await uploadToImgBB(imageROI);
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
    
    // Step 3: Visual Search via SerpApi
    let visualMatches;
    try {
      visualMatches = await fetchVisualMatches(imageUrl);
      console.log('[DAVSS] Visual matches found:', visualMatches.length);
      
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
    
    // Step 4: Calculate Score
    // First standardize to get clean hostname, then extract root domain for comparison
    const standardizedUrl = standardizeDomain(currentUrl);
    const currentDomain = standardizedUrl; // Keep standardized for display
    const scoreResult = calculateScore(visualMatches, currentDomain);
    
    // Format the result to match expected output structure
    return {
      similarityScore: scoreResult.similarityScore,
      confidenceScore: scoreResult.confidenceScore,
      currentDomain: currentDomain,
      trueDomain: scoreResult.mostFrequentDomain,
      frequencyCount: scoreResult.frequencyCount,
      totalResults: scoreResult.totalResults,
      error: scoreResult.error,
      errorMessage: scoreResult.errorMessage
    };
    
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
