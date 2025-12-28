// Popup script - Integrated scoring system with online learning

let analysisData = {
  prediction: null,
  features: null,
  offpage: null,
  visual: null,
  moduleScores: { onPage: null, visual: null, offPage: null },
  unifiedScore: 0
};

let phishingSystem = null;

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
  // Initialize weight optimizer
  phishingSystem = new OnlinePhishingSystem();
  await phishingSystem.loadWeights();

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

  // Feedback buttons
  document.getElementById('feedback-phishing').addEventListener('click', () => {
    submitFeedback(1); // 1 = phishing
  });

  document.getElementById('feedback-safe').addEventListener('click', () => {
    submitFeedback(0); // 0 = safe
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

    // Display URL
    const urlDisplay = document.getElementById('url-display');
    const statusLine = document.getElementById('status-line');
    
    if (urlDisplay) urlDisplay.textContent = url;
    if (statusLine) statusLine.textContent = url;

    // === STEP 1: Start Visual Analysis (Async) - Create Promise ===
    const visualOutput = document.getElementById('visual-output');
    if (visualOutput) visualOutput.textContent = "Running Visual Analysis (DAVSS)...";
    
    const visualPromise = new Promise((resolve) => {
      chrome.runtime.sendMessage({ 
        action: 'run_davss_analysis', 
        tabId: tab.id, 
        url: url 
      }, (response) => {
        if (chrome.runtime.lastError) {
          console.warn("Visual analysis error:", chrome.runtime.lastError);
          analysisData.visual = { error: true, errorMessage: chrome.runtime.lastError.message };
          analysisData.moduleScores.visual = null;
        } else {
          analysisData.visual = response?.davss;
          analysisData.moduleScores.visual = extractVisualScore(response?.davss);
        }
        displayVisuals(analysisData.visual);
        resolve(); // Signal completion
      });
    });

    // === STEP 2: Extract URL features ===
    const urlExtractor = new FeatureExtractor(url);
    const urlFeatures = urlExtractor.extractFeatures();

    if (!urlFeatures || urlFeatures.length !== 80) {
      showError('URL feature extraction failed');
      return;
    }

    console.log('[Phishing Detector] URL features extracted:', urlFeatures.length);

    // === STEP 3: Start off-page analysis ===
    const domain = new URL(url).hostname;
    const offpagePromise = analyzeOffpage(domain);

    // === STEP 4: Inject content script ===
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content_features.js']
      });
      console.log('[Phishing Detector] Content script injected');
      await new Promise(r => setTimeout(r, 100));
    } catch (error) {
      console.warn('[Phishing Detector] Script injection failed:', error);
    }

    // === STEP 5: Extract content features ===
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
        console.log(`[Phishing Detector] Retry ${attempts}/${maxAttempts}`);
        if (attempts < maxAttempts) {
          await new Promise(r => setTimeout(r, 300));
        }
      }
    }

    // Combine features
    let allFeatures;
    if (!contentResponse || !contentResponse.features) {
      console.warn('[Phishing Detector] Content features unavailable, using URL only');
      allFeatures = urlFeatures;
    } else {
      const contentFeatures = contentResponse.features;
      allFeatures = [
        ...urlFeatures.slice(0, 56),
        ...contentFeatures
      ];
      console.log('[Phishing Detector] Combined features:', allFeatures.length);
    }

    analysisData.features = allFeatures;
    displayFeatures(allFeatures);

    // === STEP 6: Send to Flask API (On-Page Analysis) ===
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
      
      // Wait for off-page analysis
      try {
        await offpagePromise;
      } catch (e) {
        console.warn("Off-page analysis failed", e);
      }
      
      // === WAIT FOR VISUAL ANALYSIS ===
      try {
        await visualPromise;
        console.log('[Phishing Detector] Visual analysis complete');
      } catch (e) {
        console.warn("Visual analysis failed", e);
      }
      
      // Run smart login page check
      result = smartLoginPageCheck(url, result, analysisData.offpage);
      
      // Extract on-page score (ML confidence)
      analysisData.moduleScores.onPage = result.confidence;
      
      analysisData.prediction = result;
      displayPrediction(result);
      
      // === NOW calculate unified score (all modules ready) ===
      updateUnifiedScore();
      
      console.log('[Phishing Detector] Final Result:', result);

    } catch (error) {
      console.error('[Phishing Detector] API error:', error);
      showError('Flask API not responding. Ensure it is running on localhost:5000');
      displayFeatures(allFeatures);
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
    
    const { analyzeDomain } = await import('./offpage.js');
    const result = await analyzeDomain(domain);
    
    analysisData.offpage = result;
    
    if (result.error) {
      // RDAP failed - set score to null
      analysisData.moduleScores.offPage = null;
      offpageOutput.textContent = JSON.stringify({
        error: true,
        reason: result.reason
      }, null, 2);
    } else {
      // Extract off-page score
      analysisData.moduleScores.offPage = result.normalized;
      offpageOutput.textContent = JSON.stringify({
        domain: result.domain,
        daysAge: result.daysAge,
        daysLifespan: result.daysLifespan,
        daysSinceUpdate: result.daysSinceUpdate,
        scoreAge: result.scoreAge,
        scoreLifespan: result.scoreLifespan,
        scoreUpdate: result.scoreUpdate,
        rawScore: result.rawScore,
        normalizedRisk: result.normalized,
        whitelisted: result.whitelisted
      }, null, 2);
    }
  } catch (error) {
    console.error('[Phishing Detector] Off-page analysis error:', error);
    analysisData.moduleScores.offPage = null;
    offpageOutput.textContent = JSON.stringify({
      error: true,
      reason: error.message
    }, null, 2);
  }
  
  updateUnifiedScore();
}

function extractVisualScore(davssData) {
  if (!davssData || davssData.error) return null;
  
  // Convert DAVSS result to 0-1 score
  // If whitelisted, score = 0 (safe)
  if (davssData.whitelisted) return 0;
  
  // Otherwise use similarity score (already 0-1)
  return davssData.similarityScore || 0;
}

function updateUnifiedScore() {
  const { onPage, visual, offPage } = analysisData.moduleScores;
  
  // Prepare scores array (null values will be filtered by weight optimizer)
  const scores = [onPage, visual, offPage];
  
  // Calculate unified score using weight optimizer
  const unifiedScore = phishingSystem.predict(scores);
  analysisData.unifiedScore = unifiedScore;
  
  // Display unified score
  displayUnifiedScore(unifiedScore, scores);
  
  // Display RAW data
  displayRawData(scores, unifiedScore);
}

function displayUnifiedScore(score, moduleScores) {
  // Update ring progress
  const scoreRing = document.getElementById('score-progress');
  const scoreValue = document.getElementById('score-value');
  
  if (!scoreRing || !scoreValue) return;
  
  // Convert 0-1 to 0-100
  const percentage = Math.round(score * 100);
  scoreValue.textContent = percentage;
  
  // Calculate stroke offset (534 is circumference)
  const offset = 534 - (percentage / 100) * 534;
  scoreRing.style.strokeDashoffset = offset;
  
  // Color based on risk level
  scoreRing.classList.remove('danger', 'warning', 'safe');
  if (percentage >= 70) {
    scoreRing.classList.add('danger');
  } else if (percentage >= 40) {
    scoreRing.classList.add('warning');
  } else {
    scoreRing.classList.add('safe');
  }
  
  // Display individual module scores
  displayModuleScore('onpage', moduleScores[0]);
  displayModuleScore('visual', moduleScores[1]);
  displayModuleScore('offpage', moduleScores[2]);
}

function displayModuleScore(moduleName, score) {
  const element = document.getElementById(`${moduleName}-score`);
  if (!element) return;
  
  if (score === null || score === undefined) {
    element.textContent = 'N/A';
    element.classList.add('unavailable');
    element.classList.remove('high', 'medium', 'low');
  } else {
    const percentage = Math.round(score * 100);
    element.textContent = `${percentage}%`;
    element.classList.remove('unavailable');
    
    // Color based on level
    element.classList.remove('high', 'medium', 'low');
    if (percentage >= 70) {
      element.classList.add('high');
    } else if (percentage >= 40) {
      element.classList.add('medium');
    } else {
      element.classList.add('low');
    }
  }
}

function displayPrediction(result) {
  const isPhishing = result.is_phishing;
  const confidence = result.confidence * 100;
  const riskLevel = result.risk_level || 'UNKNOWN';
  const suspiciousFeatures = result.suspicious_features || [];

  const statusLine = document.getElementById('status-line');
  if (statusLine) {
    statusLine.textContent = isPhishing ? 'PHISHING DETECTED' : 'LEGITIMATE SITE';
  }

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

  const isSuspicious = davssData.similarityScore > 0;
  const statusColor = isSuspicious ? "red" : "green";

  const report = {
    "Status": davssData.status || (isSuspicious ? "Suspicious" : "Safe"),
    "True Domain": davssData.trueDomain || "N/A",
    "Current Domain": davssData.currentDomain || "N/A",
    "Similarity Score": (davssData.similarityScore * 100).toFixed(1) + "%",
    "Confidence": (davssData.confidenceScore * 100).toFixed(1) + "%",
    "Scenario": davssData.scenario || "N/A",
    "Text Threat": davssData.textThreatDetected ? "YES" : "NO",
    "Whitelisted": davssData.whitelisted ? "YES" : "NO"
  };

  visualOutput.textContent = JSON.stringify(report, null, 2);
  visualOutput.style.color = statusColor;
}

function displayRawData(scores, unifiedScore) {
  const rawOutput = document.getElementById('raw-output');
  if (!rawOutput) return;

  const weights = phishingSystem.getWeights();
  const [onPage, visual, offPage] = scores;
  
  // Get valid scores (filter nulls)
  const validScores = [];
  const scoreNames = ['on_page', 'visual', 'off_page'];
  scores.forEach((score, idx) => {
    if (score !== null && score !== undefined && !isNaN(score)) {
      validScores.push({
        name: scoreNames[idx],
        value: score,
        weight: weights[scoreNames[idx]]
      });
    }
  });

  // Calculate individual contributions
  const contributions = validScores.map(s => ({
    module: s.name,
    score: s.value.toFixed(4),
    weight: s.weight.toFixed(4),
    contribution: (s.value * s.weight).toFixed(4)
  }));

  const rawData = {
    "Raw Module Scores": {
      "on_page": onPage !== null ? onPage.toFixed(4) : "NULL",
      "visual": visual !== null ? visual.toFixed(4) : "NULL",
      "off_page": offPage !== null ? offPage.toFixed(4) : "NULL"
    },
    "Current Weights": {
      "on_page": weights.on_page.toFixed(4),
      "visual": weights.visual.toFixed(4),
      "off_page": weights.off_page.toFixed(4)
    },
    "Calculation Breakdown": contributions,
    "Unified Score": unifiedScore.toFixed(4),
    "Unified Score (%)": (unifiedScore * 100).toFixed(2) + "%",
    "Model Status": {
      "has_learned": phishingSystem.hasLearned,
      "learning_rate": phishingSystem.lr
    }
  };

  rawOutput.textContent = JSON.stringify(rawData, null, 2);
  rawOutput.style.color = "#d4d4d4";
}

function smartLoginPageCheck(url, prediction, offpageData) {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname.toLowerCase();
    
    const isLoginPage = /\/login|\/signin|\/sign-in|\/auth|\/account/.test(path);
    
    if (!isLoginPage || !prediction.is_phishing) return prediction;
    
    if (!offpageData || offpageData.error) {
      console.log("Skipping smart check: No offpage data available");
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

    const domainAge = offpageData.daysAge || 0;
    const isHTTPS = urlObj.protocol === 'https:';
    
    if (domainAge > 180 && isHTTPS) {
      console.log(`[Smart Check] OVERRIDE: Login page on established domain (${domainAge} days)`);
      
      return {
        ...prediction,
        is_phishing: false,
        confidence: 0.15,
        class: 'legitimate',
        risk_level: 'LOW',
        suspicious_features: [
          ...((prediction.suspicious_features || []).filter(f => !f.includes('Login'))),
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

async function submitFeedback(label) {
  const feedbackStatus = document.getElementById('feedback-status');
  const btnPhishing = document.getElementById('feedback-phishing');
  const btnSafe = document.getElementById('feedback-safe');
  
  // Disable buttons
  btnPhishing.disabled = true;
  btnSafe.disabled = true;
  
  try {
    const { onPage, visual, offPage } = analysisData.moduleScores;
    const scores = [onPage, visual, offPage];
    
    // Update the model
    phishingSystem.update(scores, label);
    
    // Get updated weights
    const weights = phishingSystem.getWeights();
    console.log('[Feedback] Updated weights:', weights);
    
    // Log feedback data for tracking
    chrome.storage.local.get('feedback_count', (data) => {
      const count = (data.feedback_count || 0) + 1;
      chrome.storage.local.set({ feedback_count: count });
      console.log(`[Feedback] Total feedback submissions: ${count}`);
    });
    
    // Recalculate score with new weights
    const newScore = phishingSystem.predict(scores);
    analysisData.unifiedScore = newScore;
    displayUnifiedScore(newScore, scores);
    
    // Update RAW tab
    displayRawData(scores, newScore);
    
    // Show success message
    if (feedbackStatus) {
      feedbackStatus.textContent = `✓ Thank you! Model updated. New weights: On-Page ${(weights.on_page*100).toFixed(1)}%, Visual ${(weights.visual*100).toFixed(1)}%, Off-Page ${(weights.off_page*100).toFixed(1)}%`;
      feedbackStatus.classList.remove('error');
    }
    
    // Re-enable after 3 seconds
    setTimeout(() => {
      btnPhishing.disabled = false;
      btnSafe.disabled = false;
    }, 3000);
    
  } catch (error) {
    console.error('[Feedback] Error:', error);
    if (feedbackStatus) {
      feedbackStatus.textContent = '✗ Failed to update model';
      feedbackStatus.classList.add('error');
    }
    btnPhishing.disabled = false;
    btnSafe.disabled = false;
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