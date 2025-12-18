// Background service worker - communicates with Flask API and DAVSS

import { calculateDavssScore } from './davssService.js';
import { TRUSTED_DOMAINS } from './data/trustedList.js';

const API_URL = 'http://localhost:5000';

// Helper: Check whitelist to skip expensive visual analysis
function isWhitelisted(url) {
  try {
    const hostname = new URL(url).hostname;
    // Simple check: is the hostname (or root) in the set?
    // This handles basic cases. For complex subdomains, strict matching is used here.
    const parts = hostname.split('.');
    const root = parts.slice(-2).join('.'); // simple root extraction
    return TRUSTED_DOMAINS.has(hostname) || TRUSTED_DOMAINS.has(root);
  } catch (e) {
    return false;
  }
}

// Check API health on startup
async function checkAPIHealth() {
  try {
    const response = await fetch(`${API_URL}/health`);
    const data = await response.json();
    console.log('✅ API Health:', data);
    return data.model_loaded;
  } catch (error) {
    console.error('❌ API not reachable:', error.message);
    return false;
  }
}

// Check on install
chrome.runtime.onInstalled.addListener(() => {
  console.log('Extension installed');
  checkAPIHealth();
});

// Message handler
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  
  // --- EXISTING HANDLERS ---
  if (request.action === 'analyzeURL') {
    analyzeURL(request.url, request.features)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true; // Keep channel open
  }
  
  if (request.action === 'getStatus') {
    checkAPIHealth()
      .then(ready => sendResponse({ 
        modelLoaded: ready,
        ready: ready,
        apiUrl: API_URL
      }))
      .catch(error => sendResponse({ 
        modelLoaded: false,
        ready: false,
        error: error.message
      }));
    return true;
  }

  // --- NEW VISUAL ANALYSIS HANDLER ---
  if (request.action === 'run_davss_analysis') {
    const { tabId, url } = request;

    // 1. Check whitelist first to save API credits
    if (isWhitelisted(url)) {
      console.log(`[DAVSS] ${url} is whitelisted. Skipping visual check.`);
      sendResponse({ 
        davss: { 
          status: "Safe", 
          whitelisted: true, 
          similarityScore: 0,
          confidenceScore: 1.0,
          trueDomain: new URL(url).hostname 
        } 
      });
      return true;
    }

    // 2. Run Analysis
    console.log(`[DAVSS] Starting visual analysis for ${url}`);
    calculateDavssScore(tabId, url)
      .then(result => {
        sendResponse({ davss: result });
      })
      .catch(err => {
        console.error("DAVSS Error:", err);
        sendResponse({ davss: { error: true, errorMessage: err.message } });
      });
      
    return true; // Keep channel open
  }
});

async function analyzeURL(url, features) {
  try {
    const cacheKey = `result_${url}`;
    const cached = await chrome.storage.local.get(cacheKey);
    
    if (cached[cacheKey]) {
      const age = Date.now() - cached[cacheKey].timestamp;
      if (age < 60 * 60 * 1000) {
        return cached[cacheKey];
      }
    }

    const response = await fetch(`${API_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, features: features })
    });

    if (!response.ok) throw new Error('API request failed');

    const result = await response.json();
    
    const cacheData = {
      isPhishing: result.is_phishing,
      confidence: result.confidence,
      suspiciousFeatures: result.suspicious_features || [],
      riskLevel: result.risk_level,
      timestamp: Date.now()
    };
    
    await chrome.storage.local.set({ [cacheKey]: cacheData });
    return cacheData;

  } catch (error) {
    return {
      error: `API Error: ${error.message}`,
      isPhishing: false,
      confidence: 0,
      suspiciousFeatures: [],
      riskLevel: 'UNKNOWN'
    };
  }
}