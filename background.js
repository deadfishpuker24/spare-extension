// background.js — final clean version

import { analyzeDomain } from "./offpage.js";
import { calculateDavssScore } from "./davssService.js";
import { isDomainWhitelisted, getRootDomain } from "./utils/domainUtils.js";

let latestFeatures = null;
let latestOffPage = null;
let latestDavss = null;

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ----- STORE ON-PAGE FEATURES -----
  if (msg.type === "phiusiil_features") {
    latestFeatures = msg.data;
    chrome.storage.local.set({ latestFeatures: msg.data });
    sendResponse({ status: "stored" });
    return true;
  }

  // ----- RETURN ON-PAGE FEATURES -----
  if (msg.type === "get_latest_features") {
    sendResponse({ features: latestFeatures });
    return true;
  }

  // ----- RUN OFF-PAGE ANALYSIS (RDAP) -----
  if (msg.type === "run_offpage_analysis") {
    const url = msg.url || sender.tab?.url;
    const domain = msg.domain || (url ? getRootDomain(url) : "");
    
    // Check whitelist first
    if (url && isDomainWhitelisted(url)) {
      const rootDomain = getRootDomain(url);
      console.log(`[Whitelist] Domain ${rootDomain} is trusted. Skipping off-page analysis.`);
      
      // Set badge to Safe (Green) for whitelisted domains
      const tabId = sender.tab?.id;
      if (tabId) {
        chrome.action.setBadgeText({ text: '✓', tabId: tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#00ff00', tabId: tabId });
      }
      
      const whitelistedResult = {
        whitelisted: true,
        domain: rootDomain,
        status: "Safe",
        message: "Domain is in trusted whitelist"
      };
      latestOffPage = whitelistedResult;
      chrome.storage.local.set({ offpage_results: whitelistedResult });
      sendResponse({ offpage: whitelistedResult });
      return true;
    }
    
    const cleanDomain = (domain || "").toLowerCase().replace(/^www\./, "");
    if (!cleanDomain) {
      sendResponse({
        offpage: { error: true, reason: "Empty domain" }
      });
      return true;
    }

    analyzeDomain(cleanDomain)
      .then(result => {
        latestOffPage = result;
        chrome.storage.local.set({ offpage_results: result });
        sendResponse({ offpage: result });
      })
      .catch(err => {
        latestOffPage = { error: true, reason: "RDAP lookup failed" };
        sendResponse({ offpage: latestOffPage });
      });

    return true; // keep message channel open for async response
  }

  // ----- RETURN LAST OFF-PAGE RESULT -----
  if (msg.type === "get_offpage_results") {
    sendResponse({ offpage: latestOffPage });
    return true;
  }

  // ----- RUN DAVSS ANALYSIS -----
  if (msg.type === "run_davss_analysis") {
    const tabId = msg.tabId || sender.tab?.id;
    const url = msg.url || sender.tab?.url;

    if (!tabId || !url) {
      console.error("[DAVSS] Missing tabId or url", { tabId, url });
      sendResponse({
        davss: { error: true, errorMessage: "Missing tabId or url" }
      });
      return true;
    }

    // Check whitelist first - skip expensive DAVSS analysis if trusted
    if (isDomainWhitelisted(url)) {
      const rootDomain = getRootDomain(url);
      console.log(`[Whitelist] Domain ${rootDomain} is trusted. Skipping DAVSS analysis.`);
      
      // Set badge to Safe (Green) for whitelisted domains
      chrome.action.setBadgeText({ text: '✓', tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#00ff00', tabId: tabId });
      
      const whitelistedResult = {
        similarityScore: 0,
        confidenceScore: 1.0,
        currentDomain: rootDomain,
        trueDomain: rootDomain,
        frequencyCount: 0,
        totalResults: 0,
        error: false,
        errorMessage: null,
        whitelisted: true,
        status: "Safe"
      };
      latestDavss = whitelistedResult;
      chrome.storage.local.set({ davss_results: whitelistedResult });
      sendResponse({ davss: whitelistedResult });
      return true;
    }

    console.log("[DAVSS] Starting analysis", { tabId, url });
    calculateDavssScore(tabId, url)
      .then(result => {
        console.log("[DAVSS] Analysis complete", result);
        latestDavss = result;
        chrome.storage.local.set({ davss_results: result });
        sendResponse({ davss: result });
      })
      .catch(err => {
        console.error("[DAVSS] Analysis failed", err);
        latestDavss = { error: true, errorMessage: `DAVSS analysis failed: ${err.message}` };
        sendResponse({ davss: latestDavss });
      });

    return true; // keep message channel open for async response
  }

  // ----- RETURN LAST DAVSS RESULT -----
  if (msg.type === "get_davss_results") {
    sendResponse({ davss: latestDavss });
    return true;
  }
});
