// Background service worker - communicates with Flask API and DAVSS

import { calculateDavssScore } from './davssService.js';
import { TRUSTED_DOMAINS } from './data/trustedList.js';
import { LinUCB } from './linucb.js';
import { FeatureExtractor } from './feature_extractor.js';
import { analyzeDomain } from './offpage.js';

const API_URL = 'http://localhost:5000';

function isWhitelisted(url) {
  try {
    const hostname = new URL(url).hostname;
    const parts = hostname.split('.');
    const root = parts.slice(-2).join('.');
    return TRUSTED_DOMAINS.has(hostname) || TRUSTED_DOMAINS.has(root);
  } catch (e) { return false; }
}

chrome.runtime.onInstalled.addListener(() => {
  console.log('S.P.A.R.E Extension installed');
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'run_davss_analysis') {
    if (isWhitelisted(request.url)) {
      sendResponse({ davss: { status: "Safe", whitelisted: true, similarityScore: 0, confidenceScore: 1.0, trueDomain: new URL(request.url).hostname } });
    } else {
      calculateDavssScore(request.tabId, request.url)
        .then(res => sendResponse({ davss: res }))
        .catch(err => sendResponse({ davss: { error: true, errorMessage: err.message } }));
    }
    return true;
  }
});

const analyzedTabs = new Map();
const analysisInProgress = new Map();
const THREAT_THRESHOLD = 0.60;
const ANALYSIS_COOLDOWN = 10000;

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  const url = tab.url;
  if (!url || (!url.startsWith('http://') && !url.startsWith('https://'))) return;

  if (analysisInProgress.get(tabId)) {
    console.log('[Auto-Analyze] Already in progress, skipping');
    return;
  }

  const existing = analyzedTabs.get(tabId);
  if (existing && existing.url === url && Date.now() - existing.timestamp < ANALYSIS_COOLDOWN) {
    console.log('[Auto-Analyze] Using cooldown');
    return;
  }

  console.log('[Auto-Analyze] Starting:', url);
  
  analysisInProgress.set(tabId, true);

  try {
    const analysisResult = await performFullAnalysis(tabId, url);

    if (analysisResult.error) {
      console.warn('[Auto-Analyze] Error:', analysisResult.error);
      return;
    }

    const { unifiedScore } = analysisResult;
    analyzedTabs.set(tabId, { url: url, score: unifiedScore, timestamp: Date.now() });

    console.log(`[Auto-Analyze] Score: ${(unifiedScore * 100).toFixed(1)}%`);

    await updateIcon(tabId, unifiedScore);

    if (unifiedScore >= 0.85) {
      console.log('[Auto-Analyze] CRITICAL THREAT');
      chrome.action.openPopup();
    }

  } catch (error) {
    console.error('[Auto-Analyze] Fatal:', error);
  } finally {
    analysisInProgress.delete(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  analyzedTabs.delete(tabId);
  analysisInProgress.delete(tabId);
});

async function performFullAnalysis(tabId, url) {
  try {
    console.log(`[Analysis] Starting: ${url}`);
    
    const linucbOptimizer = new LinUCB(5, 4, 1.0);
    await linucbOptimizer.load();

    const urlExtractor = new FeatureExtractor(url);
    const urlFeatures = urlExtractor.extractFeatures();
    if (!urlFeatures || urlFeatures.length !== 80) {
      console.error('[Analysis] Feature extraction failed');
      return { error: 'Feature extraction failed' };
    }

    const visualPromise = calculateDavssScore(tabId, url).catch(e => ({ error: true, errorMessage: e.message }));
    const offpagePromise = analyzeDomain(new URL(url).hostname).catch(e => ({ error: true }));

    let contentFeatures = null;
    try {
      await chrome.scripting.executeScript({ target: { tabId }, files: ['content_features.js'] });
      const resp = await chrome.tabs.sendMessage(tabId, { action: 'extractContentFeatures' });
      if (resp && resp.features) contentFeatures = resp.features;
    } catch (e) {
      console.warn('[Analysis] Content script failed');
    }

    const allFeatures = contentFeatures ? [...urlFeatures.slice(0, 56), ...contentFeatures] : urlFeatures;

    const apiResponse = await fetch(`${API_URL}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, features: allFeatures })
    });

    if (!apiResponse.ok) {
      console.error('[Analysis] API Error:', apiResponse.status);
      return { error: 'API Error' };
    }
    
    const mlResult = await apiResponse.json();
    const visualResult = await visualPromise;
    const offpageResult = await offpagePromise;

    const onPageScore = mlResult.confidence || 0;
    const visualScore = extractVisualScore(visualResult);
    const offPageScore = !offpageResult.error ? (offpageResult.normalized || 0) : null;

    const scores = [
      onPageScore,
      visualScore !== null ? visualScore : 0,
      offPageScore !== null ? offPageScore : 0
    ];
    
    const result = linucbOptimizer.predict(scores);

    if (!result || result.score === undefined) {
      console.error('[Analysis] LinUCB failed');
      return { error: 'LinUCB prediction failed' };
    }

    const cacheKey = `analysis_cache_${url}`;
    const analysisData = {
        prediction: mlResult,
        features: allFeatures,
        offpage: offpageResult,
        visual: visualResult,
        moduleScores: { onPage: onPageScore, visual: visualScore, offPage: offPageScore },
        unifiedScore: result.score || 0,
        selectedAction: result.action !== undefined ? result.action : 4,
        weightsUsed: result.weights || [0.33, 0.33, 0.33],
        ucbValues: result.ucb_values || [],
        contextFeatures: result.context || [onPageScore, visualScore || 0, offPageScore || 0, 0]
    };

    await chrome.storage.local.set({
        [cacheKey]: {
            data: analysisData,
            timestamp: Date.now()
        }
    });
    
    console.log('[Analysis] Cached');

    return { unifiedScore: result.score || 0 };

  } catch (error) {
    console.error('[Analysis] Error:', error);
    return { error: error.message };
  }
}

async function updateIcon(tabId, score) {
    try {
        const pct = Math.round(score * 100);
        let color = '#10b981';
        let symbol = 'V';

        if (pct >= 60 && pct < 85) { 
          color = '#f59e0b'; 
          symbol = '!'; 
        } else if (pct >= 85) { 
          color = '#ef4444'; 
          symbol = 'X'; 
        }

        const canvas = new OffscreenCanvas(32, 32);
        const ctx = canvas.getContext('2d');

        ctx.beginPath();
        ctx.arc(16, 16, 16, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();

        ctx.fillStyle = 'white';
        ctx.font = 'bold 20px sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(symbol, 16, 17);

        const imageData = ctx.getImageData(0, 0, 32, 32);
        await chrome.action.setIcon({ imageData: imageData, tabId: tabId });
    } catch (e) {
        let text = score < 0.6 ? 'SAFE' : 'WARN';
        if(score >= 0.85) text = 'PHISH';
        let color = score < 0.6 ? '#10b981' : (score >= 0.85 ? '#ef4444' : '#f59e0b');
        chrome.action.setBadgeText({ text, tabId });
        chrome.action.setBadgeBackgroundColor({ color, tabId });
    }
}

function extractVisualScore(davssData) {
  if (!davssData || davssData.error) return null;
  if (!davssData.trueDomain || davssData.trueDomain === 'N/A') return null;
  if (davssData.whitelisted) return 0;
  return davssData.similarityScore || 0;
}