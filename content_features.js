// content_features.js - extracts HTML-based features from the page

class ContentFeatureExtractor {
  constructor() {
    this.hostname = window.location.hostname;
    this.domain = this.extractDomain();
  }

  extractDomain() {
    const parts = this.hostname.split('.');
    if (parts.length >= 2) {
      return parts[parts.length - 2];
    }
    return this.hostname;
  }

  // Helper: check if URL is internal
  isInternal(url) {
    if (!url) return false;
    if (url.startsWith('/') || url.startsWith('#')) return true;
    if (url.startsWith('javascript:') || url.startsWith('mailto:')) return false;
    try {
      const urlObj = new URL(url, window.location.href);
      return urlObj.hostname === this.hostname || urlObj.hostname.includes(this.domain);
    } catch {
      return false;
    }
  }

  // Feature 57: nb_hyperlinks
  nb_hyperlinks() {
    const hrefs = document.querySelectorAll('[href]').length;
    const srcs = document.querySelectorAll('[src]').length;
    return hrefs + srcs;
  }

  // Feature 58: ratio_intHyperlinks
  ratio_intHyperlinks() {
    const all = document.querySelectorAll('a[href], link[href], img[src], script[src]');
    if (all.length === 0) return 0;
    
    let internal = 0;
    all.forEach(el => {
      const url = el.href || el.src;
      if (this.isInternal(url)) internal++;
    });
    
    return internal / all.length;
  }

  // Feature 59: ratio_extHyperlinks
  ratio_extHyperlinks() {
    return 1 - this.ratio_intHyperlinks();
  }

  // Feature 60: ratio_nullHyperlinks
  ratio_nullHyperlinks() {
    const nullFormats = ['', '#', '#nothing', '#doesnotexist', '#null', '#void', 
                         'javascript:void(0)', 'javascript:void(0);', 'javascript:;'];
    const all = document.querySelectorAll('a[href]');
    if (all.length === 0) return 0;
    
    let nullCount = 0;
    all.forEach(el => {
      if (nullFormats.includes(el.getAttribute('href')?.trim())) {
        nullCount++;
      }
    });
    
    return nullCount / all.length;
  }

  // Feature 61: nb_extCSS
  nb_extCSS() {
    let count = 0;
    document.querySelectorAll('link[rel="stylesheet"]').forEach(link => {
      const href = link.getAttribute('href');
      if (href && !this.isInternal(href)) count++;
    });
    return count;
  }

  // Feature 62-65: redirections and errors (skip - require network requests)
  ratio_intRedirection() { return 0; }
  ratio_extRedirection() { return 0; }
  ratio_intErrors() { return 0; }
  ratio_extErrors() { return 0; }

  // Feature 66: login_form
  login_form() {
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      // Check for password input
      if (form.querySelector('input[type="password"]')) return 1;
      
      // Check for login-related patterns
      const action = form.getAttribute('action') || '';
      if (/login|signin|log-in|sign-in/i.test(action)) return 1;
    }
    return 0;
  }

  // Feature 67: external_favicon
  external_favicon() {
    const favicons = document.querySelectorAll('link[rel*="icon"]');
    for (const fav of favicons) {
      const href = fav.getAttribute('href');
      if (href && !this.isInternal(href)) return 1;
    }
    return 0;
  }

  // Feature 68: links_in_tags
  links_in_tags() {
    const links = document.querySelectorAll('link[href]');
    if (links.length === 0) return 0;
    
    let internal = 0;
    links.forEach(link => {
      if (this.isInternal(link.getAttribute('href'))) internal++;
    });
    
    return (internal / links.length) * 100;
  }

  // Feature 69: submit_email
  submitting_to_email() {
    const forms = document.querySelectorAll('form[action]');
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (action && (action.includes('mailto:') || action.includes('mail()'))) {
        return 1;
      }
    }
    return 0;
  }

  // Feature 70: ratio_intMedia
  ratio_intMedia() {
    const media = document.querySelectorAll('img[src], audio[src], video[src], embed[src]');
    if (media.length === 0) return 0;
    
    let internal = 0;
    media.forEach(el => {
      if (this.isInternal(el.getAttribute('src'))) internal++;
    });
    
    return (internal / media.length) * 100;
  }

  // Feature 71: ratio_extMedia
  ratio_extMedia() {
    return 100 - this.ratio_intMedia();
  }

  // Feature 72: sfh (Server Form Handler)
  sfh() {
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (!action || action === '' || action === 'about:blank') return 1;
    }
    return 0;
  }

  // Feature 73: iframe
  iframe() {
    // Check for invisible iframes
    const iframes = document.querySelectorAll('iframe');
    for (const iframe of iframes) {
      const width = iframe.getAttribute('width') || iframe.style.width;
      const height = iframe.getAttribute('height') || iframe.style.height;
      const border = iframe.getAttribute('frameborder') || iframe.getAttribute('border');
      
      if ((width === '0' || width === '0px') && 
          (height === '0' || height === '0px') &&
          (border === '0' || iframe.style.border === 'none')) {
        return 1;
      }
    }
    return 0;
  }

  // Feature 74: popup_window
  popup_window() {
    const html = document.documentElement.outerHTML;
    return html.toLowerCase().includes('prompt(') ? 1 : 0;
  }

  // Feature 75: safe_anchor
  safe_anchor() {
    const anchors = document.querySelectorAll('a[href]');
    if (anchors.length === 0) return 0;
    
    let unsafe = 0;
    anchors.forEach(a => {
      const href = a.getAttribute('href');
      if (href && (href.includes('#') || href.includes('javascript') || href.includes('mailto'))) {
        unsafe++;
      }
    });
    
    return (unsafe / anchors.length) * 100;
  }

  // Feature 76: onmouseover
  onmouseover() {
    const html = document.documentElement.outerHTML;
    return /onmouseover\s*=\s*["']window\.status/i.test(html) ? 1 : 0;
  }

  // Feature 77: right_clic
  right_clic() {
    const html = document.documentElement.outerHTML;
    return /event\.button\s*==\s*2/.test(html) ? 1 : 0;
  }

  // Feature 78: empty_title
  empty_title() {
    const title = document.querySelector('title');
    return (!title || !title.textContent.trim()) ? 1 : 0;
  }

  // Feature 79: domain_in_title
  domain_in_title() {
    const title = document.querySelector('title');
    if (!title) return 1;
    return title.textContent.toLowerCase().includes(this.domain.toLowerCase()) ? 0 : 1;
  }

  // Feature 80: domain_with_copyright
  domain_with_copyright() {
    const html = document.documentElement.outerHTML;
    const copyrightMatch = html.match(/[Â©Â®â„¢]/);
    if (!copyrightMatch) return 0;
    
    const idx = copyrightMatch.index;
    const context = html.substring(Math.max(0, idx - 50), Math.min(html.length, idx + 50));
    return context.toLowerCase().includes(this.domain.toLowerCase()) ? 0 : 1;
  }

  // Extract all 24 content features
  extractContentFeatures() {
    try {
      return [
        this.nb_hyperlinks(),           // 57
        this.ratio_intHyperlinks(),     // 58
        this.ratio_extHyperlinks(),     // 59
        this.ratio_nullHyperlinks(),    // 60
        this.nb_extCSS(),               // 61
        this.ratio_intRedirection(),    // 62
        this.ratio_extRedirection(),    // 63
        this.ratio_intErrors(),         // 64
        this.ratio_extErrors(),         // 65
        this.login_form(),              // 66
        this.external_favicon(),        // 67
        this.links_in_tags(),           // 68
        this.submitting_to_email(),     // 69
        this.ratio_intMedia(),          // 70
        this.ratio_extMedia(),          // 71
        this.sfh(),                     // 72
        this.iframe(),                  // 73
        this.popup_window(),            // 74
        this.safe_anchor(),             // 75
        this.onmouseover(),             // 76
        this.right_clic(),              // 77
        this.empty_title(),             // 78
        this.domain_in_title(),         // 79
        this.domain_with_copyright()    // 80
      ];
    } catch (error) {
      console.error('Content feature extraction error:', error);
      // Return zeros if extraction fails
      return new Array(24).fill(0);
    }
  }
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'extractContentFeatures') {
    const extractor = new ContentFeatureExtractor();
    const features = extractor.extractContentFeatures();
    sendResponse({ features });
  }
  return true;
});