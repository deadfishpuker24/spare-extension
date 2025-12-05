/**
 * DAVSS Service - Domain-Affinity Visual Similarity Scoring
 * 
 * This module detects brand impersonation by:
 * 1. Capturing a screenshot of the current page
 * 2. Sending it to a Visual Search Engine (VSE)
 * 3. Analyzing the top search results to check if they match the current domain
 * 
 * If the most frequent domain in results differs from the current domain,
 * it indicates potential brand impersonation.
 */

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
 * Mock Visual Search Engine (VSE) function
 * 
 * TODO: Replace this mock function with actual API call to Visual Search Engine
 * Expected API format:
 * - Method: POST
 * - Body: { image: base64Image }
 * - Response: JSON array of results with domain/source URLs
 * 
 * @param {string} base64Image - Base64 encoded image data URL
 * @returns {Promise<Array>} - Promise resolving to array of result objects with domain information
 */
async function fetchVisualSearchResults(base64Image) {
  // Simulate API delay
  await new Promise(resolve => setTimeout(resolve, 500));
  
  // Mock response: Return a mix of domains
  // In real implementation, this would parse HTML/JSON from VSE API
  const mockResults = [
    { url: 'https://www.google.com/search?q=example', domain: 'google.com' },
    { url: 'https://example.com/page1', domain: 'example.com' },
    { url: 'https://www.example.com/page2', domain: 'example.com' },
    { url: 'https://example.com/page3', domain: 'example.com' },
    { url: 'https://legitimate-brand.com/page1', domain: 'legitimate-brand.com' },
    { url: 'https://www.example.com/page4', domain: 'example.com' },
    { url: 'https://example.com/page5', domain: 'example.com' },
    { url: 'https://other-site.com/page1', domain: 'other-site.com' },
    { url: 'https://example.com/page6', domain: 'example.com' },
    { url: 'https://example.com/page7', domain: 'example.com' },
  ];
  
  // TODO: Actual implementation should:
  // 1. Make POST request to VSE API endpoint
  // 2. Send base64Image in request body
  // 3. Parse response (HTML or JSON)
  // 4. Extract domain information from each result
  // 5. Return array of { url, domain } objects
  
  return mockResults;
}

/**
 * Extracts domains from VSE results
 * 
 * @param {Array} results - Array of result objects from VSE
 * @returns {Array<string>} - Array of standardized domain strings
 */
function extractDomainsFromResults(results) {
  const domains = [];
  
  for (const result of results) {
    let domain = '';
    
    // If result already has a domain field, use it
    if (result.domain) {
      domain = result.domain;
    }
    // Otherwise, try to extract from URL
    else if (result.url) {
      try {
        const url = new URL(result.url);
        domain = url.hostname;
      } catch (error) {
        // If URL parsing fails, try string manipulation
        const match = result.url.match(/https?:\/\/([^\/]+)/);
        if (match) {
          domain = match[1];
        }
      }
    }
    
    if (domain) {
      domains.push(standardizeDomain(domain));
    }
  }
  
  return domains;
}

/**
 * Finds the most frequent domain and its count in a list
 * 
 * @param {Array<string>} domainList - Array of domain strings
 * @returns {Object} - Object with { domain: string, count: number }
 */
function findMostFrequentDomain(domainList) {
  if (!domainList || domainList.length === 0) {
    return { domain: '', count: 0 };
  }
  
  // Count frequency of each domain
  const frequencyMap = {};
  for (const domain of domainList) {
    if (domain) {
      frequencyMap[domain] = (frequencyMap[domain] || 0) + 1;
    }
  }
  
  // Find domain with highest frequency
  let mostFrequentDomain = '';
  let maxCount = 0;
  
  for (const [domain, count] of Object.entries(frequencyMap)) {
    if (count > maxCount) {
      maxCount = count;
      mostFrequentDomain = domain;
    }
  }
  
  return {
    domain: mostFrequentDomain,
    count: maxCount
  };
}

/**
 * Main DAVSS calculation function
 * 
 * Calculates the Domain-Affinity Visual Similarity Score by:
 * 1. Capturing a screenshot of the current tab
 * 2. Sending it to VSE for visual search
 * 3. Analyzing top N results to find most frequent domain
 * 4. Comparing current domain with most frequent domain
 * 
 * @param {number} currentTabId - The ID of the current tab to capture
 * @param {string} currentUrl - The URL of the current page
 * @param {number} topN - Number of top results to analyze (default: 10)
 * @returns {Promise<Object>} - Promise resolving to score object:
 *   {
 *     similarityScore: number,  // 0 = legitimate, >0 = impersonation detected
 *     confidenceScore: number,   // Frequency of most common domain
 *     currentDomain: string,     // Standardized current domain
 *     trueDomain: string,        // Most frequent domain from VSE results
 *     frequencyCount: number,    // Count of most frequent domain
 *     totalResults: number,      // Total results analyzed
 *     error: boolean,            // Whether an error occurred
 *     errorMessage: string      // Error message if error occurred
 *   }
 */
export async function calculateDavssScore(currentTabId, currentUrl, topN = 10) {
  try {
    // Step 1: Image Capture
    // Capture the visible tab as a base64 data URL
    let imageROI;
    try {
      imageROI = await chrome.tabs.captureVisibleTab(null, {
        format: 'png',
        quality: 100
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
    
    // Step 2: Visual Search Engine Interaction
    let vseResults;
    try {
      vseResults = await fetchVisualSearchResults(imageROI);
      
      if (!vseResults || !Array.isArray(vseResults) || vseResults.length === 0) {
        return {
          similarityScore: -1,
          confidenceScore: 0,
          currentDomain: '',
          trueDomain: '',
          frequencyCount: 0,
          totalResults: 0,
          error: true,
          errorMessage: 'VSE returned no results'
        };
      }
    } catch (vseError) {
      return {
        similarityScore: -1,
        confidenceScore: 0,
        currentDomain: '',
        trueDomain: '',
        frequencyCount: 0,
        totalResults: 0,
        error: true,
        errorMessage: `VSE request failed: ${vseError.message}`
      };
    }
    
    // Step 3: Domain Parsing
    // Extract domains from top N results
    const topResults = vseResults.slice(0, topN);
    const domainList = extractDomainsFromResults(topResults);
    
    if (domainList.length === 0) {
      return {
        similarityScore: -1,
        confidenceScore: 0,
        currentDomain: '',
        trueDomain: '',
        frequencyCount: 0,
        totalResults: topResults.length,
        error: true,
        errorMessage: 'No valid domains found in VSE results'
      };
    }
    
    // Step 4: Frequency Analysis
    const { domain: mostFrequentDomain, count: frequencyCount } = findMostFrequentDomain(domainList);
    
    if (!mostFrequentDomain) {
      return {
        similarityScore: -1,
        confidenceScore: 0,
        currentDomain: '',
        trueDomain: '',
        frequencyCount: 0,
        totalResults: domainList.length,
        error: true,
        errorMessage: 'Could not determine most frequent domain'
      };
    }
    
    // Step 5: Scoring Logic
    const confidenceScore = frequencyCount / domainList.length;
    
    // Step 6: Standardization
    const domainCurrent = standardizeDomain(currentUrl);
    const trueDomain = standardizeDomain(mostFrequentDomain);
    
    // Step 7: Final Comparison
    let similarityScore;
    if (domainCurrent === trueDomain) {
      // Legitimate: Current domain matches the most frequent domain from VSE
      similarityScore = 0;
    } else {
      // Impersonation detected: Current domain differs from VSE results
      similarityScore = confidenceScore;
    }
    
    return {
      similarityScore,
      confidenceScore,
      currentDomain: domainCurrent,
      trueDomain: trueDomain,
      frequencyCount,
      totalResults: domainList.length,
      error: false,
      errorMessage: null
    };
    
  } catch (error) {
    // Catch any unexpected errors
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

