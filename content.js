// content.js
// S.P.A.R.E – PhiUSIIL-style On-Page Feature Extraction

function countMatches(str, regex) {
  if (!str) return 0;
  const m = str.match(regex);
  return m ? m.length : 0;
}

function jaccardTokenSimilarity(a, b) {
  if (!a || !b) return 0;
  const toksA = a.toLowerCase().split(/[^\w]+/).filter(Boolean);
  const toksB = b.toLowerCase().split(/[^\w]+/).filter(Boolean);
  if (!toksA.length || !toksB.length) return 0;

  const setA = new Set(toksA);
  const setB = new Set(toksB);
  let inter = 0;
  for (const t of setA) {
    if (setB.has(t)) inter++;
  }
  const union = new Set([...setA, ...setB]).size;
  return union === 0 ? 0 : inter / union;
}

//newaddnstarts

// Character continuation rate (repeated characters sequence indicator)
function computeCharContinuationRate(url) {
  let repeats = 0;
  for (let i = 1; i < url.length; i++) {
    if (url[i] === url[i - 1]) repeats++;
  }
  return repeats / url.length;
}

// Probability URL uses common characters (letters + numbers)
function computeURLCharProb(url) {
  const normal = countMatches(url, /[A-Za-z0-9]/g);
  return normal / url.length;
}

// TLD legitimacy probability
function computeTLDLegitimateProb(tld) {
  const trusted = ["com", "in", "co", "org", "net", "edu", "gov"];
  return trusted.includes(tld.toLowerCase()) ? 1 : 0.2; //0.2 for risky sites
}

// Obfuscation detection: %xx encoded characters
function computeObfuscation(url) {
  const matches = url.match(/%[0-9A-Fa-f]{2}/g);
  const count = matches ? matches.length : 0;
  return {
    has: count > 0 ? 1 : 0,
    count,
    ratio: count / url.length
  };
}
//newaddntillhere

function extractPhiUSIILFeatures() {
  const urlObj = new URL(window.location.href);
  const urlStr = urlObj.href;
  const domain = urlObj.hostname || "";
  const protocol = urlObj.protocol.replace(":", "");

  const html = document.documentElement.outerHTML || "";
  const lines = html.split("\n");
  const lineOfCode = lines.length;
  const largestLineLength = lines.reduce(
    (max, l) => (l.length > max ? l.length : max),
    0
  );

  const urlLength = urlStr.length;
  const domainLength = domain.length;
  const tldPart = (() => {
    const parts = domain.split(".");
    return parts.length > 1 ? parts[parts.length - 1] : "";
  })();
  const tldLength = tldPart.length;

  const numLetters = countMatches(urlStr, /[A-Za-z]/g);
  const numDigits = countMatches(urlStr, /\d/g);
  const numEqual = countMatches(urlStr, /=/g);
  const numQMark = countMatches(urlStr, /\?/g);
  const numAmp = countMatches(urlStr, /&/g);

  const punctuationChars = `!"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~`;
  let numOtherSpecial = 0;
  for (const ch of urlStr) {
    if (
      punctuationChars.includes(ch) &&
      ch !== "=" &&
      ch !== "?" &&
      ch !== "&"
    ) {
      numOtherSpecial++;
    }
  }

  const totalSpecial = numEqual + numQMark + numAmp + numOtherSpecial;
  const safeLen = urlLength || 1;
  const noOfSubDomain = Math.max(domain.split(".").length - 2, 0);

  const titleEl = document.querySelector("title");
  const titleText = (titleEl && titleEl.textContent) || document.title || "";
  const hasTitle = titleText.trim().length > 0 ? 1 : 0;

  const hasFavicon =
    document.querySelector("link[rel*='icon']") ||
    document.querySelector("link[href*='favicon']")
      ? 1
      : 0;

  const robotsMeta = document.querySelector('meta[name="robots"]');
  const robots = robotsMeta ? 1 : 0;

  const viewportTag = document.querySelector('meta[name="viewport"]');
  let isResponsive = 0;
  if (viewportTag) {
    const c = (viewportTag.getAttribute("content") || "").toLowerCase();
    if (
      c.includes("width=device-width") ||
      c.includes("initial-scale") ||
      c.includes("minimum-scale") ||
      c.includes("maximum-scale")
    ) {
      isResponsive = 1;
    }
  }

  const hasDescription = document.querySelector('meta[name="description"]')
    ? 1
    : 0;

  const noOfPopUp = countMatches(html, /window\.open\s*\(/gi);

  const noOfFrame =
    document.querySelectorAll("frame").length +
    document.querySelectorAll("iframe").length;

  const forms = [...document.querySelectorAll("form")];
  let hasExternalFormSubmit = 0,
    hasSubmitButton = 0,
    hasHiddenFields = 0,
    hasPasswordField = 0;

  forms.forEach((f) => {
    const action = (f.getAttribute("action") || "").trim();

    if (action) {
      try {
        const actionUrl = new URL(action, location.href);
        if (actionUrl.hostname !== domain) hasExternalFormSubmit = 1;
      } catch {
        hasExternalFormSubmit = 1;
      }
    }

    if (f.querySelector('input[type="submit"], button[type="submit"]'))
      hasSubmitButton = 1;
    if (f.querySelector('input[type="hidden"]')) hasHiddenFields = 1;
    if (f.querySelector('input[type="password"]')) hasPasswordField = 1;
  });

  const anchors = [...document.querySelectorAll("a[href]")];
  const socialKeywords = [
    "facebook.com",
    "twitter.com",
    "x.com",
    "instagram.com",
    "linkedin.com",
    "t.me",
    "telegram",
    "wa.me",
    "whatsapp.com",
    "youtube.com",
    "reddit.com"
  ];
  let hasSocialNet = 0;
  let noOfSelfRef = 0;
  let noOfEmptyRef = 0;
  let noOfExternalRef = 0;

  anchors.forEach((a) => {
    const href = a.getAttribute("href") || "";
    const lowerHref = href.toLowerCase();

    if (!href || href === "#" || lowerHref.startsWith("javascript:void")) {
      noOfEmptyRef++;
    }

    try {
      const linkUrl = new URL(href, window.location.href);
      if (linkUrl.hostname === domain) {
        noOfSelfRef++;
      } else if (linkUrl.hostname) {
        noOfExternalRef++;
      }

      if (
        socialKeywords.some((kw) =>
          linkUrl.hostname.toLowerCase().includes(kw)
        )
      ) {
        hasSocialNet = 1;
      }
    } catch (_) {}
  });

  const bodyText = (document.body && document.body.innerText) || "";
  const bpKeywords = [
    "bank",
    "banking",
    "paypal",
    "paytm",
    "upi",
    "netbanking",
    "credit card",
    "debit card",
    "crypto",
    "bitcoin",
    "ethereum",
    "binance"
  ];
  const combinedText = (urlStr + " " + bodyText).toLowerCase();
  const bankPayCrypto = bpKeywords.some((kw) =>
    combinedText.includes(kw)
  )
    ? 1
    : 0;

  const hasCopyrightInfo =
    combinedText.includes("©") || combinedText.includes("copyright") ? 1 : 0;

  const noOfImage = document.querySelectorAll("img").length;
  const noOfCSS =
    document.querySelectorAll('link[rel="stylesheet"]').length +
    document.querySelectorAll("style").length;
  const noOfJS = document.querySelectorAll("script").length;

  const metaRefresh = document.querySelectorAll(
    'meta[http-equiv="refresh"]'
  ).length;
  const noOfURLRedirect = metaRefresh;

  const noOfSelfRedirect = anchors.filter((a) => {
    try {
      const linkUrl = new URL(a.href);
      return linkUrl.href === urlStr;
    } catch {
      return false;
    }
  }).length;

  const isHTTPS = protocol.toLowerCase().startsWith("https") ? 1 : 0;

  const letterRatioInURL = numLetters / safeLen;
  const digitRatioInURL = numDigits / safeLen;
  const specialCharRatioInURL = totalSpecial / safeLen;

  const isDomainIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(domain) ? 1 : 0;

  const features = {
    FileName: null,
    URL: urlStr,

    URLLength: urlLength,
    Domain: domain,
    DomainLength: domainLength,
    IsDomainIP: isDomainIP,
    TLD: tldPart,
    TLDLength: tldLength,
    NoOfSubDomain: noOfSubDomain,

    //URLSimilarityIndex: null,
    CharContinuationRate: computeCharContinuationRate(urlStr),
    TLDLegitimateProb: computeTLDLegitimateProb(tldPart),
    URLCharProb: computeURLCharProb(urlStr),

    HasObfuscation: computeObfuscation(urlStr).has,
    NoOfObfuscatedChar: computeObfuscation(urlStr).count,
    ObfuscationRatio: computeObfuscation(urlStr).ratio,


    NoOfLettersInURL: numLetters,
    LetterRatioInURL: letterRatioInURL,
    NoOfDigitsInURL: numDigits,
    DigitRatioInURL: digitRatioInURL,
    NoOfEqualSignInURL: numEqual,
    NoOfQMarkInURL: numQMark,
    NoOfAmpersandInURL: numAmp,
    NoOfOtherSpecialCharsInURL: numOtherSpecial,
    SpecialCharRatioInURL: specialCharRatioInURL,

    IsHTTPS: isHTTPS,

    LineOfCode: lineOfCode,
    LargestLineLength: largestLineLength,

    HasTitle: hasTitle,
    Title: titleText,
    DomainTitleMatchScore: jaccardTokenSimilarity(domain, titleText),
    URLTitleMatchScore: jaccardTokenSimilarity(urlStr, titleText),

    HasFavicon: hasFavicon,
    Robots: robots,
    IsResponsive: isResponsive,

    NoOfURLRedirect: noOfURLRedirect,
    NoOfSelfRedirect: noOfSelfRedirect,

    HasDescription: hasDescription,
    NoOfPopUp: noOfPopUp,
    NoOfFrame: noOfFrame,

    HasExternalFormSubmit: hasExternalFormSubmit,
    HasSocialNet: hasSocialNet,
    HasSubmitButton: hasSubmitButton,
    HasHiddenFields: hasHiddenFields,
    HasPasswordField: hasPasswordField,

    Bank_Pay_Crypto: bankPayCrypto,
    HasCopyrightInfo: hasCopyrightInfo,

    NoOfImage: noOfImage,
    NoOfCSS: noOfCSS,
    NoOfJS: noOfJS,

    NoOfSelfRef: noOfSelfRef,
    NoOfEmptyRef: noOfEmptyRef,
    NoOfExternalRef: noOfExternalRef,

    label: null
  };

  // ensure no null/undefined (ML safety later)
  for (const k in features) {
    if (features[k] === null || features[k] === undefined) {
      features[k] = 0;
    }
  }

  return features;
}

// run once per page
(function runFeatureExtraction() {
  try {
    const feats = extractPhiUSIILFeatures();
    console.log("[S.P.A.R.E] On-page features:", feats);

    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
      chrome.runtime.sendMessage(
        { type: "phiusiil_features", data: feats },
        () => {}
      );
    }
  } catch (e) {
    console.error("[S.P.A.R.E] Feature extraction error:", e);
  }
})();
