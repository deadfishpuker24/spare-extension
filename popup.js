// popup.js - Redesigned with Caching System (Full Version)

import { LinUCB } from './linucb.js';
import { FeatureExtractor } from './feature_extractor.js';


let analysisData = {
  prediction: null,
  features: null,
  offpage: null,
  visual: null,
  moduleScores: { onPage: null, visual: null, offPage: null },
  unifiedScore: 0
};

let linucbOptimizer = null;
let currentTabId = null; // Store tab ID to prevent result lingering

document.addEventListener('DOMContentLoaded', async () => {
  // Initialize LinUCB optimizer
  linucbOptimizer = new LinUCB(
    5,    // n_actions: 5 weight configurations
    4,    // n_features: [ml, vis, off, disagreement]
    1.0   // alpha: exploration parameter
  );
  // Load saved model
  await linucbOptimizer.load();
  console.log('[LinUCB] Optimizer initialized');

  // Setup modal tabs
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tabName = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
      document.getElementById(`${tabName}-tab`).classList.add('active');
    });
  });

  // Modal controls
  document.getElementById('view-raw-btn').addEventListener('click', () => {
    document.getElementById('raw-modal').style.display = 'flex';
  });

  document.getElementById('close-modal').addEventListener('click', () => {
    document.getElementById('raw-modal').style.display = 'none';
  });

  // Re-analyze button - clears cache and reloads
  document.getElementById('reanalyze-btn').addEventListener('click', async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const cacheKey = `analysis_cache_${tab.url}`;
    await chrome.storage.local.remove(cacheKey);
    console.log('[Cache] Cache cleared for current URL');
    location.reload();
  });

  // === NEW: Feedback Listeners ===
  const feedbackPhishing = document.getElementById('feedback-phishing');
  const feedbackSafe = document.getElementById('feedback-safe');
  
  if (feedbackPhishing) {
    feedbackPhishing.addEventListener('click', () => submitFeedback(1));
  }
  if (feedbackSafe) {
    feedbackSafe.addEventListener('click', () => submitFeedback(0));
  }

  // Start analysis
  startAnalysis();
});

// === NEW: Export Function for Console ===
window.exportLinUCBModel = async function() {
  if (!linucbOptimizer) {
    console.error("Optimizer not initialized");
    return;
  }
  
  const data = {
    A: linucbOptimizer.A,
    b: linucbOptimizer.b,
    total_trials: linucbOptimizer.total_trials,
    alpha: linucbOptimizer.alpha,
    timestamp: Date.now()
  };

  const jsonStr = JSON.stringify(data, null, 2);
  const blob = new Blob([jsonStr], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  
  const a = document.createElement('a');
  a.href = url;
  a.download = "linucb_trained_model.json";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  console.log("✅ Model exported successfully!");
};

async function startAnalysis() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const url = tab.url;
    currentTabId = tab.id; // Capture ID for specific icon updates

    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      showError('Cannot analyze this page type');
      return;
    }

    // Display URL
    document.getElementById('current-url').textContent = url;

    // === CHECK CACHE FIRST ===
    const cacheKey = `analysis_cache_${url}`;
    const cached = await chrome.storage.local.get(cacheKey);
    
    if (cached[cacheKey]) {
      const cacheAge = Date.now() - cached[cacheKey].timestamp;
      const CACHE_DURATION = 10 * 60 * 1000; // 10 minutes
      
      if (cacheAge < CACHE_DURATION) {
        console.log('[Cache] ✅ Using cached analysis (age: ' + Math.round(cacheAge/1000) + 's)');
        
        // Show cache indicator in header subtitle
        const headerSubtitle = document.querySelector('.header-subtitle');
        if (headerSubtitle) {
          headerSubtitle.textContent = `Cached Result (${Math.round(cacheAge/1000)}s ago)`;
          headerSubtitle.style.color = '#f59e0b';
        }
        
        // Restore cached data with safety checks
        const cachedData = cached[cacheKey].data;
        
        analysisData = {
          prediction: cachedData.prediction || null,
          features: cachedData.features || null,
          offpage: cachedData.offpage || null,
          visual: cachedData.visual || null,
          moduleScores: cachedData.moduleScores || { onPage: null, visual: null, offPage: null },
          unifiedScore: cachedData.unifiedScore || 0,
          selectedAction: cachedData.selectedAction || 0,
          weightsUsed: cachedData.weightsUsed || [0.33, 0.33, 0.33],
          ucbValues: cachedData.ucbValues || [],
          contextFeatures: cachedData.contextFeatures || null
        };
        
        // === FIX: Regenerate Context if Missing (Legacy Cache Support) ===
        if (!analysisData.contextFeatures || analysisData.contextFeatures.length === 0) {
            console.log('[Cache] Context missing, recalculating for RL...');
            updateUnifiedScore();
        }

        // Update UI with cached data
        try {
          updateVerdictUI();
          updateAdvancedDetails();
          updateRawDataModal();
        } catch (err) {
          console.error('[Cache] Error restoring UI:', err);
          await chrome.storage.local.remove(cacheKey);
          console.log('[Cache] Corrupted cache cleared, running fresh analysis');
        }
        
        if (analysisData.unifiedScore > 0) {
          console.log('[Cache] ✅ Restored analysis from cache');
          return; // Skip all API calls
        }
      } else {
        console.log('[Cache] Cache expired, running fresh analysis');
      }
    } else {
      console.log('[Cache] No cache found, running fresh analysis');
    }

    // === NO CACHE - RUN FULL ANALYSIS ===

    // === STEP 1: Start Visual Analysis (Async) ===
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
        resolve();
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

      // Wait for off-page and visual analysis
      try {
        await offpagePromise;
      } catch (e) {
        console.warn("Off-page analysis failed", e);
      }

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

      // === Calculate unified score ===
      updateUnifiedScore();

      // Update UI with all data
      updateVerdictUI();
      updateAdvancedDetails();
      updateRawDataModal();

      // === SAVE TO CACHE ===
      await chrome.storage.local.set({
        [cacheKey]: {
          data: {
            prediction: analysisData.prediction,
            features: analysisData.features,
            offpage: analysisData.offpage,
            visual: analysisData.visual,
            moduleScores: analysisData.moduleScores,
            unifiedScore: analysisData.unifiedScore,
            selectedAction: analysisData.selectedAction,
            weightsUsed: analysisData.weightsUsed,
            ucbValues: analysisData.ucbValues,
            contextFeatures: analysisData.contextFeatures
          },
          timestamp: Date.now()
        }
      });
      console.log('[Cache] 💾 Analysis cached for 10 minutes');

      console.log('[Phishing Detector] ✅ Analysis Complete');

    } catch (error) {
      console.error('[Phishing Detector] API error:', error);
      showError('Flask API not responding. Ensure it is running on localhost:5000');
    }

  } catch (error) {
    console.error('[Phishing Detector] Fatal error:', error);
    showError('Analysis error: ' + error.message);
  }
}

async function analyzeOffpage(domain) {
  try {
    const { analyzeDomain } = await import('./offpage.js');
    const result = await analyzeDomain(domain);

    analysisData.offpage = result;

    if (result.error) {
      analysisData.moduleScores.offPage = null;
    } else {
      analysisData.moduleScores.offPage = result.normalized;
    }

    console.log('[Phishing Detector] Off-page analysis complete');

  } catch (error) {
    console.error('[Phishing Detector] Off-page analysis error:', error);
    analysisData.moduleScores.offPage = null;
  }
}

function extractVisualScore(davssData) {
  if (!davssData || davssData.error) {
    console.log('[Visual Score] Error or no data returned');
    return null;
  }

  if (!davssData.trueDomain || davssData.trueDomain === 'N/A' || davssData.trueDomain === null) {
    console.warn('[Visual Score] No trueDomain detected - returning N/A');
    return null;
  }

  if (davssData.whitelisted) {
    console.log('[Visual Score] Domain is whitelisted - score = 0');
    return 0;
  }

  const score = davssData.similarityScore || 0;
  console.log('[Visual Score] Similarity score:', score);
  return score;
}

function updateUnifiedScore() {
  const { onPage, visual, offPage } = analysisData.moduleScores;
  const scores = [onPage, visual, offPage];

  // Use LinUCB to select weights and calculate score
  const result = linucbOptimizer.predict(scores);

  analysisData.unifiedScore = result.score;
  analysisData.selectedAction = result.action;
  analysisData.weightsUsed = result.weights;
  analysisData.ucbValues = result.ucb_values;
  analysisData.contextFeatures = result.context;

  console.log('[LinUCB] Prediction:', {
    score: result.score,
    action: result.action,
    weights: result.weights
  });
}

// === NEW: Submit Feedback Function with Cache Persist ===
async function submitFeedback(label) {
  const feedbackStatus = document.getElementById('feedback-status');
  const btnPhishing = document.getElementById('feedback-phishing');
  const btnSafe = document.getElementById('feedback-safe');
  
  if (!feedbackStatus || !btnPhishing || !btnSafe) return;

  btnPhishing.disabled = true;
  btnSafe.disabled = true;
  
  try {
    const { onPage, visual, offPage } = analysisData.moduleScores;
    const scores = [onPage, visual, offPage];
    
    // Safety check: ensure context exists before feedback
    if (!analysisData.contextFeatures) updateUnifiedScore();
    
    const currentScore = analysisData.unifiedScore;
    let reward = (label === 1) ? currentScore : (1 - currentScore);
    
    linucbOptimizer.update(analysisData.selectedAction, analysisData.contextFeatures, reward);
    await linucbOptimizer.save();
    
    // Re-predict to show updated score immediately
    const new_result = linucbOptimizer.predict(scores);
    analysisData.unifiedScore = new_result.score;
    analysisData.selectedAction = new_result.action;
    analysisData.weightsUsed = new_result.weights;
    analysisData.ucbValues = new_result.ucb_values;
    analysisData.contextFeatures = new_result.context;
    
    console.log(`[LinUCB] Feedback: label=${label}, reward=${reward.toFixed(3)}`);

    updateVerdictUI();
    updateRawDataModal();

    // UPDATE CACHE to ensure feedback persists on reload
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const cacheKey = `analysis_cache_${tab.url}`;
    
    const existingCache = await chrome.storage.local.get(cacheKey);
    if (existingCache[cacheKey]) {
        await chrome.storage.local.set({
            [cacheKey]: {
                data: analysisData,
                timestamp: existingCache[cacheKey].timestamp
            }
        });
    }
    
    feedbackStatus.textContent = `✓ Model updated! Trials: ${linucbOptimizer.total_trials}`;
    feedbackStatus.style.color = '#10b981';
    
    setTimeout(() => {
      btnPhishing.disabled = false;
      btnSafe.disabled = false;
      feedbackStatus.textContent = '';
    }, 3000);
    
  } catch (error) {
    console.error('[Feedback] Error:', error);
    feedbackStatus.textContent = '✗ Update failed';
    feedbackStatus.style.color = '#ef4444';
    btnPhishing.disabled = false;
    btnSafe.disabled = false;
  }
}

// === NEW: Update Extension Icon (Dynamic Generation) ===
function updateExtensionIcon(percentage) {
  if (!currentTabId) return;

  // Determine state
  let color, symbol;
  if (percentage < 60) {
    color = '#10b981'; // Green
    symbol = '✔'; // Safe
  } else if (percentage < 85) {
    color = '#f59e0b'; // Orange
    symbol = '!'; // Warn
  } else {
    color = '#ef4444'; // Red
    symbol = '✕'; // Phish
  }

  // 1. Clear any text badge to avoid clutter
  chrome.action.setBadgeText({ text: '', tabId: currentTabId });

  // 2. Generate dynamic icon using Canvas
  const canvas = document.createElement('canvas');
  canvas.width = 32;
  canvas.height = 32;
  const ctx = canvas.getContext('2d');

  // Draw circle background
  ctx.beginPath();
  ctx.arc(16, 16, 16, 0, 2 * Math.PI);
  ctx.fillStyle = color;
  ctx.fill();

  // Draw symbol
  ctx.fillStyle = 'white';
  ctx.font = 'bold 20px sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(symbol, 16, 17);

  // Set as icon for THIS tab only
  const imageData = ctx.getImageData(0, 0, 32, 32);
  chrome.action.setIcon({ imageData: imageData, tabId: currentTabId });
}

function updateVerdictUI() {
  const score = analysisData.unifiedScore;
  const percentage = Math.round(score * 100);

  // Update Icon (replacing old Badge logic)
  updateExtensionIcon(percentage);

  // Get DOM elements
  const container = document.querySelector('.container');
  const threatScore = document.getElementById('threat-score');
  const verdictHeadline = document.getElementById('verdict-headline');
  const verdictRecommendation = document.getElementById('verdict-recommendation');

  // Update threat score
  threatScore.textContent = percentage + '%';

  // Determine risk tier and apply theme
  container.classList.remove('theme-safe', 'theme-warning', 'theme-danger');

  if (percentage < 60) {
    // TIER 1: SAFE
    container.classList.add('theme-safe');
    verdictHeadline.textContent = 'Website is Safe';
    verdictRecommendation.textContent = 'No visual or domain threats detected.';
  } else if (percentage < 85) {
    // TIER 2: SUSPICIOUS
    container.classList.add('theme-warning');
    verdictHeadline.textContent = 'Suspicious Activity Detected';
    verdictRecommendation.textContent = 'This site mimics a known brand but the hosting is unusual. Proceed with caution.';
  } else {
    // TIER 3: CRITICAL PHISHING
    container.classList.add('theme-danger');
    verdictHeadline.textContent = 'CRITICAL: Deceptive Site Detected';
    verdictRecommendation.textContent = 'This is a confirmed phishing attempt. LEAVE THIS SITE IMMEDIATELY.';
  }
}

function updateAdvancedDetails() {
  const { onPage, visual, offPage } = analysisData.moduleScores;

  // True Domain
  const trueDomain = analysisData.visual?.trueDomain || 'N/A';
  document.getElementById('true-domain').textContent = trueDomain;

  // ML Confidence
  const mlConfidence = onPage !== null ? `${(onPage * 100).toFixed(1)}%` : 'N/A';
  document.getElementById('ml-confidence').textContent = mlConfidence;

  // TLD Status
  const tldStatus = analysisData.offpage?.error
    ? 'Unable to verify'
    : (analysisData.offpage?.whitelisted ? 'Whitelisted' : 'Active');
  document.getElementById('tld-status').textContent = tldStatus;

  // Module Scores
  document.getElementById('module-onpage').textContent =
    onPage !== null ? `${(onPage * 100).toFixed(1)}%` : 'N/A';
  document.getElementById('module-visual').textContent =
    visual !== null ? `${(visual * 100).toFixed(1)}%` : 'N/A';
  document.getElementById('module-offpage').textContent =
    offPage !== null ? `${(offPage * 100).toFixed(1)}%` : 'N/A';

  // Total Results (from DAVSS)
  const totalResults = analysisData.visual?.totalResults || 'N/A';
  document.getElementById('total-results').textContent = totalResults;

  // Suspicious Features
  const suspiciousFeatures = analysisData.prediction?.suspicious_features || [];
  if (suspiciousFeatures.length > 0) {
    document.getElementById('suspicious-features').textContent =
      suspiciousFeatures.map((f, i) => `${i + 1}. ${f}`).join('\n');
  } else {
    document.getElementById('suspicious-features').textContent = 'None detected';
  }
}

function updateRawDataModal() {
  // Prediction Tab
  const predictionOutput = document.getElementById('prediction-output');
  if (predictionOutput && analysisData.prediction) {
    const result = analysisData.prediction;
    const output = {
      "Classification": result.class,
      "Confidence": `${(result.confidence * 100).toFixed(2)}%`,
      "Risk Level": result.risk_level,
      "Is Phishing": result.is_phishing ? 'YES' : 'NO',
      "Suspicious Features": result.suspicious_features || []
    };
    predictionOutput.textContent = JSON.stringify(output, null, 2);
  }

  // Features Tab
  const featuresOutput = document.getElementById('features-output');
  if (featuresOutput && analysisData.features) {
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
    analysisData.features.forEach((value, index) => {
      const formattedValue = typeof value === 'number' && value % 1 !== 0
        ? parseFloat(value.toFixed(4))
        : value;
      featureObj[featureNames[index]] = formattedValue;
    });

    featuresOutput.textContent = JSON.stringify(featureObj, null, 2);
  }

  // Off-Page Tab
  const offpageOutput = document.getElementById('offpage-output');
  if (offpageOutput && analysisData.offpage) {
    const result = analysisData.offpage;
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
        normalizedRisk: result.normalized,
        whitelisted: result.whitelisted
      }, null, 2);
    }
  }

  // Visual Tab
  const visualOutput = document.getElementById('visual-output');
  if (visualOutput && analysisData.visual) {
    const davssData = analysisData.visual;

    if (davssData.error) {
      visualOutput.textContent = `Error: ${davssData.errorMessage || "Unknown error"}`;
    } else if (!davssData.trueDomain || davssData.trueDomain === 'N/A') {
      const report = {
        "Status": "Inconclusive - Visual Analysis N/A",
        "Reason": "Could not determine true domain from visual search",
        "Current Domain": davssData.currentDomain || "N/A",
        "Note": "Final score will be based on ML and Off-Page analysis only"
      };
      visualOutput.textContent = JSON.stringify(report, null, 2);
    } else {
      const report = {
        "Status": davssData.status || (davssData.similarityScore > 0 ? "Suspicious" : "Safe"),
        "True Domain": davssData.trueDomain || "N/A",
        "Current Domain": davssData.currentDomain || "N/A",
        "Similarity Score": (davssData.similarityScore * 100).toFixed(1) + "%",
        "Confidence": (davssData.confidenceScore * 100).toFixed(1) + "%",
        "Scenario": davssData.scenario || "N/A",
        "Text Threat": davssData.textThreatDetected ? "YES" : "NO",
        "Whitelisted": davssData.whitelisted ? "YES" : "NO"
      };
      visualOutput.textContent = JSON.stringify(report, null, 2);
    }
  }

  // Raw Tab
  const rawOutput = document.getElementById('raw-output');
  if (rawOutput && analysisData.weightsUsed) {
    const { onPage, visual, offPage } = analysisData.moduleScores;
    const rawData = {
      "Raw Module Scores": {
        "on_page": onPage !== null ? onPage.toFixed(4) : "NULL",
        "visual": visual !== null ? visual.toFixed(4) : "NULL",
        "off_page": offPage !== null ? offPage.toFixed(4) : "NULL"
      },
      "LinUCB Decision": {
        "selected_action": analysisData.selectedAction,
        "action_description": getActionDescription(analysisData.selectedAction),
        "weights_used": {
          "ml": analysisData.weightsUsed[0].toFixed(3),
          "visual": analysisData.weightsUsed[1].toFixed(3),
          "offpage": analysisData.weightsUsed[2].toFixed(3)
        }
      },
      "Context Features": {
        "ml_score": analysisData.contextFeatures[0].toFixed(4),
        "visual_score": analysisData.contextFeatures[1].toFixed(4),
        "offpage_score": analysisData.contextFeatures[2].toFixed(4),
        "disagreement": analysisData.contextFeatures[3].toFixed(4)
      },
      "UCB Values (All Actions)": analysisData.ucbValues.map(ucb => ({
        action: ucb.action,
        predicted_reward: ucb.predicted_reward.toFixed(4),
        uncertainty: ucb.uncertainty.toFixed(4),
        ucb_score: ucb.ucb.toFixed(4),
        invalid: ucb.invalid || false
      })),
      "Final Unified Score": analysisData.unifiedScore.toFixed(4),
      "Unified Score (%)": (analysisData.unifiedScore * 100).toFixed(2) + "%",
      "Model Status": {
        "total_trials": linucbOptimizer.total_trials,
        "exploration_alpha": linucbOptimizer.alpha
      }
    };
    rawOutput.textContent = JSON.stringify(rawData, null, 2);
  }
}

function getActionDescription(action) {
  const descriptions = [
    'ML Heavy (60-20-20)',
    'Visual Heavy (20-60-20)',
    'OffPage Heavy (20-20-60)',
    'ML+Visual Blend (50-30-20)',
    'Balanced (33-33-33)'
  ];
  return descriptions[action] || 'Unknown';
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

function showError(message) {
  const verdictHeadline = document.getElementById('verdict-headline');
  const verdictRecommendation = document.getElementById('verdict-recommendation');
  const threatScore = document.getElementById('threat-score');

  if (threatScore) {
    threatScore.textContent = '!';
  }

  if (verdictHeadline) {
    verdictHeadline.textContent = 'Analysis Error';
  }

  if (verdictRecommendation) {
    verdictRecommendation.textContent = message;
  }
}