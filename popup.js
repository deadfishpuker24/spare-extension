// Popup script - Mendeley dataset phishing detector

let analysisData = {
  prediction: null,
  features: null,
  offpage: null,
  visual: null
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  // Setup tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
      document.getElementById(`${tabName}-tab`).classList.add('active');
    });
  });

  // Re-analyze button
  document.getElementById('reanalyze-btn').addEventListener('click', () => {
    location.reload();
  });

  // Start analysis
  startAnalysis();
});

async function startAnalysis() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url;

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      showError('Cannot analyze this page type');
      return;
    }

    // Display URL (check elements exist first)
    const urlDisplay = document.getElementById('url-display');
    const statusLine = document.getElementById('status-line');
    
    if (urlDisplay) urlDisplay.textContent = url;
    if (statusLine) statusLine.textContent = url;

    // === NEW: Start Visual Analysis (Async) ===
    // This runs in the background while the ML model works
    /*const visualOutput = document.getElementById('visual-output');
    if (visualOutput) visualOutput.textContent = "Running Visual Analysis (DAVSS)...";
    
    chrome.runtime.sendMessage({ 
      action: 'run_davss_analysis', 
      tabId: tab.id, 
      url: url 
    }, (response) => {
      // Handle the async response when it eventually arrives
      if (chrome.runtime.lastError) {
        console.warn("Visual analysis error:", chrome.runtime.lastError);
        displayVisuals({ error: true, errorMessage: chrome.runtime.lastError.message });
      } else {
        analysisData.visual = response?.davss;
        displayVisuals(response?.davss);
      }
    });*/

    // STEP 1: Extract URL features (56 features)
    const urlExtractor = new FeatureExtractor(url);
    const urlFeatures = urlExtractor.extractFeatures();

    if (!urlFeatures || urlFeatures.length !== 80) {
      showError('URL feature extraction failed');
      return;
    }

    console.log('[Phishing Detector] URL features extracted:', urlFeatures.length);

    // STEP 1.5: Extract domain for off-page analysis
    // NOTE: We capture the promise here so we can wait for it later
    const domain = new URL(url).hostname;
    const offpageAnalysisPromise = analyzeOffpage(domain);

    // STEP 2: Inject content script if not already injected
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content_features.js']
      });
      console.log('[Phishing Detector] Content script injected');
      // Wait a bit for script to initialize
      await new Promise(r => setTimeout(r, 100));
    } catch (error) {
      console.warn('[Phishing Detector] Script injection failed:', error);
    }

    // STEP 3: Extract content features from page (24 features) with retry
    let contentResponse = null;
    let attempts = 0;
    const maxAttempts = 3;

    while (!contentResponse && attempts < maxAttempts) {
      try {
        contentResponse = await new Promise((resolve, reject) => {
          chrome.tabs.sendMessage(tab.id, { action: 'extractContentFeatures' }, (response) => {
            if (chrome.runtime.lastError) {
              reject(chrome.runtime.lastError);
            } else {
              resolve(response);
            }
          });
        });
        
        if (contentResponse && contentResponse.features) {
          console.log('[Phishing Detector] Content features extracted successfully');
        }
      } catch (error) {
        attempts++;
        console.log(`[Phishing Detector] Retry ${attempts}/${maxAttempts} - Content script not ready`);
        if (attempts < maxAttempts) {
          await new Promise(r => setTimeout(r, 300)); // Wait 300ms between retries
        }
      }
    }

    // Process features
    let allFeatures;
    if (!contentResponse || !contentResponse.features) {
      console.warn('[Phishing Detector] Content features unavailable after retries, using URL only');
      allFeatures = urlFeatures; // Already has 80 (56 real + 24 zeros)
    } else {
      // Combine: 56 URL features + 24 content features
      const contentFeatures = contentResponse.features;
      allFeatures = [
        ...urlFeatures.slice(0, 56),
        ...contentFeatures
      ];
      console.log('[Phishing Detector] Combined features:', allFeatures.length);
    }

    analysisData.features = allFeatures;
    displayFeatures(allFeatures);

    // STEP 4: Send to Flask API
    try {
      const apiResponse = await fetch('http://localhost:5000/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: url,
          features: allFeatures
        })
      });

      if (!apiResponse.ok) {
        throw new Error('API returned error status');
      }

      let result = await apiResponse.json();
      
      // === SMART CHECK INTEGRATION ===
      // Wait for offpage analysis to finish so we have the data
      try {
          await offpageAnalysisPromise;
      } catch (e) {
          console.warn("Offpage analysis failed, skipping smart check", e);
      }
      
      // Run the Heuristic Override
      result = smartLoginPageCheck(url, result, analysisData.offpage);
      
      analysisData.prediction = result;
      displayPrediction(result);
      console.log('[Phishing Detector] Final Result:', result);

    } catch (error) {
      console.error('[Phishing Detector] API error:', error);
      showError('Flask API not responding. Ensure it is running on localhost:5000');
      displayFeatures(allFeatures); // Still show features even if API fails
    }

  } catch (error) {
    console.error('[Phishing Detector] Fatal error:', error);
    showError('Analysis error: ' + error.message);
  }
}

async function analyzeOffpage(domain) {
  const offpageOutput = document.getElementById('offpage-output');
  if (!offpageOutput) return;

  try {
    offpageOutput.textContent = 'Analyzing domain...';
    
    // Import and call the analyzeDomain function
    const { analyzeDomain } = await import('./offpage.js');
    const result = await analyzeDomain(domain);
    
    analysisData.offpage = result;
    
    if (result.error) {
      offpageOutput.textContent = JSON.stringify({
        error: true,
        reason: result.reason
      }, null, 2);
    } else {
      offpageOutput.textContent = JSON.stringify({
        domain: result.domain,
        daysAge: result.daysAge,
        daysLifespan: result.daysLifespan,
        daysSinceUpdate: result.daysSinceUpdate,
        scoreAge: result.scoreAge,
        scoreLifespan: result.scoreLifespan,
        scoreUpdate: result.scoreUpdate,
        rawScore: result.rawScore,
        normalizedRisk: result.normalized
      }, null, 2);
    }
  } catch (error) {
    console.error('[Phishing Detector] Off-page analysis error:', error);
    offpageOutput.textContent = JSON.stringify({
      error: true,
      reason: error.message
    }, null, 2);
  }
}

function displayPrediction(result) {
  const isPhishing = result.is_phishing;
  const confidence = result.confidence * 100;
  const riskLevel = result.risk_level || 'UNKNOWN';
  const suspiciousFeatures = result.suspicious_features || [];

  // Update status line (check exists)
  const statusLine = document.getElementById('status-line');
  if (statusLine) {
    statusLine.textContent = isPhishing ? 'PHISHING DETECTED' : 'LEGITIMATE SITE';
  }

  // Update result card
  const resultTitle = document.getElementById('result-title');
  const confidenceFill = document.getElementById('confidence-fill');
  const confidenceText = document.getElementById('confidence-text');

  if (resultTitle) {
    if (isPhishing) {
      resultTitle.textContent = 'PHISHING';
      resultTitle.className = 'danger';
    } else {
      resultTitle.textContent = 'LEGITIMATE';
      resultTitle.className = 'safe';
    }
  }

  if (confidenceFill) {
    confidenceFill.className = isPhishing ? 'confidence-fill danger' : 'confidence-fill safe';
    confidenceFill.style.width = confidence + '%';
  }

  if (confidenceText) {
    confidenceText.textContent = `Confidence: ${confidence.toFixed(1)}% | Risk: ${riskLevel}`;
  }

  // Display analysis
  const analysisOutput = document.getElementById('analysis-output');
  if (analysisOutput) {
    let output = '';
    output += `Classification: ${result.class}\n`;
    output += `Confidence: ${confidence.toFixed(2)}%\n`;
    output += `Risk Level: ${riskLevel}\n`;
    output += `Is Phishing: ${isPhishing ? 'YES' : 'NO'}\n`;
    output += `\n`;

    if (suspiciousFeatures.length > 0) {
      output += `Suspicious Indicators (${suspiciousFeatures.length}):\n`;
      suspiciousFeatures.forEach((feature, i) => {
        output += `  ${i + 1}. ${feature}\n`;
      });
    } else {
      output += `No suspicious indicators found.\n`;
    }

    analysisOutput.textContent = output;
  }
}

function displayFeatures(features) {
  const featureNames = [
    'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
    'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
    'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon',
    'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space',
    'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token',
    'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port',
    'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
    'nb_subdomains', 'prefix_suffix', 'random_domain',
    'shortening_service', 'path_extension',
    'nb_redirection', 'nb_external_redirection', 'length_words_raw',
    'char_repeat', 'shortest_words_raw', 'shortest_word_host',
    'shortest_word_path', 'longest_words_raw', 'longest_word_host',
    'longest_word_path', 'avg_words_raw', 'avg_word_host',
    'avg_word_path', 'phish_hints', 'domain_in_brand',
    'brand_in_subdomain', 'brand_in_path', 'suspecious_tld',
    'statistical_report',
    'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks',
    'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection',
    'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
    'login_form', 'external_favicon', 'links_in_tags',
    'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh',
    'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
    'right_clic', 'empty_title', 'domain_in_title',
    'domain_with_copyright'
  ];

  const featureObj = {};
  features.forEach((value, index) => {
    const formattedValue = typeof value === 'number' && value % 1 !== 0 
      ? parseFloat(value.toFixed(4)) 
      : value;
    featureObj[featureNames[index]] = formattedValue;
  });

  const featuresOutput = document.getElementById('features-output');
  if (featuresOutput) {
    featuresOutput.textContent = JSON.stringify(featureObj, null, 2);
  }
}

function showError(message) {
  const resultTitle = document.getElementById('result-title');
  const statusLine = document.getElementById('status-line');
  const analysisOutput = document.getElementById('analysis-output');
  
  if (resultTitle) {
    resultTitle.textContent = 'ERROR';
    resultTitle.className = 'danger';
  }
  
  if (statusLine) {
    statusLine.textContent = 'Analysis Failed';
  }
  
  if (analysisOutput) {
    analysisOutput.textContent = message;
  }
}

// === NEW VISUAL DISPLAY FUNCTION ===
function displayVisuals(davssData) {
  const visualOutput = document.getElementById('visual-output');
  if (!visualOutput) return;

  if (!davssData) {
    visualOutput.textContent = "No data returned.";
    return;
  }

  if (davssData.error) {
    visualOutput.textContent = `Error: ${davssData.errorMessage || "Unknown error"}`;
    visualOutput.style.color = "red";
    return;
  }

  // Determine status color (if score > 0 it is suspicious)
  const isSuspicious = davssData.similarityScore > 0;
  const statusColor = isSuspicious ? "red" : "green";

  const report = {
    "Status": davssData.status || (isSuspicious ? "Suspicious" : "Safe"),
    "True Domain": davssData.trueDomain || "N/A",
    "Current Domain": davssData.currentDomain || "N/A",
    "Confidence": (davssData.confidenceScore * 100).toFixed(1) + "%",
    "Scenario": davssData.scenario || "N/A",
    "Text Threat": davssData.textThreatDetected ? "YES" : "NO"
  };

  visualOutput.textContent = JSON.stringify(report, null, 2);
  visualOutput.style.color = statusColor;
}

// === SMART HEURISTIC FUNCTION ===
function smartLoginPageCheck(url, prediction, offpageData) {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname.toLowerCase();
    
    // 1. Is it a login page?
    const isLoginPage = /\/login|\/signin|\/sign-in|\/auth|\/account/.test(path);
    
    // If it's NOT a login page, or the ML model already thinks it's safe, return original
    if (!isLoginPage || !prediction.is_phishing) return prediction;
    
    // 2. Check off-page data availability
    if (!offpageData || offpageData.error) {
        console.log("Skipping smart check: No offpage data available");
        // FALLBACK: If API fails, check for HTTPS to avoid blind blocking
        if (urlObj.protocol === 'https:') {
             return {
                ...prediction,
                is_phishing: false,
                risk_level: 'MEDIUM',
                confidence: 0.5,
                suspiciousFeatures: ["Warning: Verification service unavailable"]
            };
        }
        return prediction;
    }

    // 3. The Rules
    const domainAge = offpageData.daysAge || 0;
    const isHTTPS = urlObj.protocol === 'https:';
    
    // Rule: If older than 6 months (180 days) AND HTTPS
    if (domainAge > 180 && isHTTPS) {
      console.log(`[Smart Check] OVERRIDE: Login page on established domain (${domainAge} days)`);
      
      return {
        ...prediction,
        is_phishing: false,
        confidence: 0.15, // Force low confidence (15%)
        class: 'legitimate',
        risk_level: 'LOW',
        suspicious_features: [
            ...((prediction.suspicious_features || []).filter(f => !f.includes('Login'))), // Remove login warnings
            `Verified: Established Domain (${domainAge} days old)`
        ]
      };
    }
    
    return prediction;

  } catch (e) {
    console.error("Smart check error:", e);
    return prediction;
  }
}