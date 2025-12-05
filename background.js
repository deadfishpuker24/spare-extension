// background.js — final clean version

import { analyzeDomain } from "./offpage.js";
import { calculateDavssScore } from "./davssService.js";

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
    const cleanDomain = (msg.domain || "").toLowerCase().replace(/^www\./, "");
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
    const topN = msg.topN || 10;

    if (!tabId || !url) {
      sendResponse({
        davss: { error: true, errorMessage: "Missing tabId or url" }
      });
      return true;
    }

    calculateDavssScore(tabId, url, topN)
      .then(result => {
        latestDavss = result;
        chrome.storage.local.set({ davss_results: result });
        sendResponse({ davss: result });
      })
      .catch(err => {
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
