// Popup script - Mendeley dataset phishing detector

let analysisData = {
  prediction: null,
  features: null,
  offpage: null
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

    // STEP 1: Extract URL features (56 features)
    const urlExtractor = new FeatureExtractor(url);
    const urlFeatures = urlExtractor.extractFeatures();

    if (!urlFeatures || urlFeatures.length !== 80) {
      showError('URL feature extraction failed');
      return;
    }

    console.log('[Phishing Detector] URL features extracted:', urlFeatures.length);

    // STEP 1.5: Extract domain for off-page analysis
    const domain = new URL(url).hostname;
    analyzeOffpage(domain);

    // STEP 2: Extract content features from page (24 features)
    chrome.tabs.sendMessage(tab.id, { action: 'extractContentFeatures' }, async (response) => {
      let allFeatures;

      if (chrome.runtime.lastError || !response || !response.features) {
        console.warn('[Phishing Detector] Content features unavailable, using URL only');
        allFeatures = urlFeatures; // Already has 80 (56 real + 24 zeros)
      } else {
        // Combine: 56 URL features + 24 content features
        const contentFeatures = response.features;
        allFeatures = [
          ...urlFeatures.slice(0, 56),
          ...contentFeatures
        ];
        console.log('[Phishing Detector] Combined features:', allFeatures.length);
      }

      analysisData.features = allFeatures;
      displayFeatures(allFeatures);

      // STEP 3: Send to Flask API
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

        const result = await apiResponse.json();
        analysisData.prediction = result;
        displayPrediction(result);
        console.log('[Phishing Detector] Prediction:', result);

      } catch (error) {
        console.error('[Phishing Detector] API error:', error);
        showError('Flask API not responding. Ensure it is running on localhost:5000');
        displayFeatures(allFeatures); // Still show features even if API fails
      }
    });

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