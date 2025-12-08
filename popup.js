// popup.js — display on-page + off-page results

document.addEventListener("DOMContentLoaded", () => {
  const output = document.getElementById("output");
  output.textContent = "Loading...";

  function show(onpage, offpage, davss) {
    const payload = {
      OnPage: onpage || "No data yet",
      OffPage: offpage || { error: true, reason: "RDAP not run or failed" },
      Visual: davss || { error: true, errorMessage: "DAVSS not run or failed" }
    };
    output.textContent = JSON.stringify(payload, null, 2);
  }

  // First: get stored on-page + off-page + davss (if any)
  chrome.storage.local.get(["latestFeatures", "offpage_results", "davss_results"], (res) => {
    const storedOn = res.latestFeatures || null;
    const storedOff = res.offpage_results || null;
    const storedDavss = res.davss_results || null;
    show(storedOn, storedOff, storedDavss);
  });

  // Then: ask background for freshest on-page value
  chrome.runtime.sendMessage({ type: "get_latest_features" }, (resp1) => {
    const onpage = resp1?.features || null;

    // Now trigger off-page RDAP and DAVSS for the active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0] || !tabs[0].url) {
        show(onpage, null, null);
        return;
      }

      const tab = tabs[0];
      
      // Check if URL is valid for analysis (skip chrome://, extension://, etc.)
      let domain = null;
      try {
        const urlObj = new URL(tab.url);
        if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
          domain = urlObj.hostname.toLowerCase().replace(/^www\./, "");
        }
      } catch (e) {
        // Invalid URL, skip analysis
        show(onpage, null, { error: true, errorMessage: "Invalid URL for analysis" });
        return;
      }

      if (!domain) {
        show(onpage, null, { error: true, errorMessage: "URL protocol not supported for analysis" });
        return;
      }

      // Run off-page analysis (pass URL for whitelist checking)
      chrome.runtime.sendMessage(
        { type: "run_offpage_analysis", domain, url: tab.url },
        (resp2) => {
          const offpage = resp2?.offpage || null;

          // Run DAVSS analysis
          chrome.runtime.sendMessage(
            {
              type: "run_davss_analysis",
              tabId: tab.id,
              url: tab.url
            },
            (resp3) => {
              const davss = resp3?.davss || null;
              show(onpage, offpage, davss);
            }
          );
        }
      );
    });
  });
});
