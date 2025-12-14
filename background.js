// Background service worker - communicates with Flask API

const API_URL = 'http://localhost:5000';

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
  if (request.action === 'analyzeURL') {
    analyzeURL(request.url, request.features)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ error: error.message }));
    return true; // Keep channel open for async response
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
});

async function analyzeURL(url, features) {
  try {
    // Check cache first
    const cacheKey = `result_${url}`;
    const cached = await chrome.storage.local.get(cacheKey);
    
    if (cached[cacheKey]) {
      const age = Date.now() - cached[cacheKey].timestamp;
      // Use cache if less than 1 hour old
      if (age < 60 * 60 * 1000) {
        console.log('📦 Using cached result');
        return cached[cacheKey];
      }
    }

    // Call Flask API
    console.log('🔍 Calling API for analysis...');
    const response = await fetch(`${API_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        url: url,
        features: features
      })
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'API request failed');
    }

    const result = await response.json();
    
    // Cache result
    const cacheData = {
      isPhishing: result.is_phishing,
      confidence: result.confidence,
      suspiciousFeatures: result.suspicious_features || [],
      riskLevel: result.risk_level,
      timestamp: Date.now()
    };
    
    await chrome.storage.local.set({ [cacheKey]: cacheData });
    
    console.log('✅ Analysis complete:', result.class);
    return cacheData;

  } catch (error) {
    console.error('❌ Analysis error:', error);
    
    // Fallback: basic heuristic if API fails
    return {
      error: `API Error: ${error.message}. Make sure Flask server is running on ${API_URL}`,
      isPhishing: false,
      confidence: 0,
      suspiciousFeatures: [],
      riskLevel: 'UNKNOWN'
    };
  }
}

// Clean old cache entries periodically
if (chrome.alarms) {
  chrome.alarms.create('cleanCache', { periodInMinutes: 60 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'cleanCache') {
      chrome.storage.local.get(null, (items) => {
        const now = Date.now();
        const toRemove = [];
        
        for (const [key, value] of Object.entries(items)) {
          if (key.startsWith('result_') && value.timestamp) {
            // Remove entries older than 24 hours
            if (now - value.timestamp > 24 * 60 * 60 * 1000) {
              toRemove.push(key);
            }
          }
        }
        
        if (toRemove.length > 0) {
          chrome.storage.local.remove(toRemove);
          console.log(`🧹 Cleaned ${toRemove.length} old cache entries`);
        }
      });
    }
  });
}