// Feature extraction based on Mendeley dataset paper
// Implements URL-based and content-based features

const HINTS = ['wp', 'login', 'includes', 'admin', 'content', 'site', 'images', 'js', 
               'alibaba', 'css', 'myaccount', 'dropbox', 'themes', 'plugins', 'signin', 'view'];

const SUSPICIOUS_TLDS = ['fit','tk', 'gp', 'ga', 'work', 'ml', 'date', 'wang', 'men', 'icu', 
                         'online', 'click', 'country', 'stream', 'download', 'xin', 'racing', 
                         'jetzt', 'ren', 'mom', 'party', 'review', 'trade', 'accountants', 
                         'science', 'ninja', 'xyz', 'faith', 'zip', 'cricket', 'win', 
                         'accountant', 'realtor', 'top', 'christmas', 'gdn', 'link', 'asia', 
                         'club', 'la', 'ae', 'exposed', 'pe', 'rs', 'audio', 'website', 'bj', 
                         'mx', 'media'];

const BRANDS = ['accenture','adidas','adobe','alibaba','amazon','apple','audi','bbc','bmw',
                'booking','canon','cisco','citi','coca-cola','dell','disney','dropbox',
                'ebay','facebook','fedex','ford','github','google','gucci','hp','hsbc',
                'ibm','ikea','instagram','intel','linkedin','mcdonalds','microsoft',
                'netflix','nike','oracle','paypal','pepsi','samsung','shell','sony',
                'spotify','starbucks','target','tesla','twitter','ups','visa','walmart',
                'wikipedia','yahoo','youtube'];

class FeatureExtractor {
  constructor(url, dom = null) {
    this.url = url;
    this.dom = dom;
    this.parsed = this.parseURL(url);
  }

  parseURL(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      const parts = hostname.split('.');
      
      // Extract TLD and domain
      const tld = parts.length > 1 ? parts[parts.length - 1] : '';
      const domain = parts.length > 1 ? parts[parts.length - 2] : parts[0];
      const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : '';
      
      // Extract words from domain, subdomain, path
      const pathParts = urlObj.pathname.split(/[-.\/?=@&%:_]/);
      const domainParts = domain.split(/[-.\/?=@&%:_]/);
      const subdomainParts = subdomain.split(/[-.\/?=@&%:_]/);
      
      const words_raw = [...domainParts, ...pathParts, ...subdomainParts].filter(w => w);
      const words_raw_host = [...domainParts, ...subdomainParts].filter(w => w);
      const words_raw_path = pathParts.filter(w => w);
      
      return {
        full: url,
        protocol: urlObj.protocol.replace(':', ''),
        hostname: hostname,
        domain: domain,
        subdomain: subdomain,
        tld: tld,
        path: urlObj.pathname,
        words_raw: words_raw,
        words_raw_host: words_raw_host,
        words_raw_path: words_raw_path
      };
    } catch (e) {
      return null;
    }
  }

  // URL-based features
  url_length(s) { return s.length; }
  
  having_ip_address() {
    const ipPattern = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}/;
    return ipPattern.test(this.parsed.hostname) ? 1 : 0;
  }
  
  count_dots() { return (this.url.match(/\./g) || []).length; }
  count_hyphens() { return (this.url.match(/-/g) || []).length; }
  count_at() { return (this.url.match(/@/g) || []).length; }
  count_exclamation() { return (this.url.match(/\?/g) || []).length; }
  count_and() { return (this.url.match(/&/g) || []).length; }
  count_or() { return (this.url.match(/\|/g) || []).length; }
  count_equal() { return (this.url.match(/=/g) || []).length; }
  count_underscore() { return (this.url.match(/_/g) || []).length; }
  count_tilde() { return (this.url.match(/~/g) || []).length > 0 ? 1 : 0; }
  count_percentage() { return (this.url.match(/%/g) || []).length; }
  count_slash() { return (this.url.match(/\//g) || []).length; }
  count_star() { return (this.url.match(/\*/g) || []).length; }
  count_colon() { return (this.url.match(/:/g) || []).length; }
  count_comma() { return (this.url.match(/,/g) || []).length; }
  count_semicolumn() { return (this.url.match(/;/g) || []).length; }
  count_dollar() { return (this.url.match(/\$/g) || []).length; }
  count_space() { return (this.url.match(/ /g) || []).length + (this.url.match(/%20/g) || []).length; }
  
  check_www() {
    return this.parsed.words_raw.filter(w => w.includes('www')).length;
  }
  
  check_com() {
    return this.parsed.words_raw.filter(w => w.includes('com')).length;
  }
  
  count_double_slash() {
    const matches = this.url.match(/\/\//g) || [];
    if (matches.length > 0) {
      const lastIndex = this.url.lastIndexOf('//');
      return lastIndex > 6 ? 1 : 0;
    }
    return 0;
  }
  
  count_http_token() {
    return (this.parsed.path.match(/http/gi) || []).length;
  }
  
  https_token() {
    return this.parsed.protocol === 'https' ? 0 : 1;
  }
  
  ratio_digits(s) {
    const digits = (s.match(/\d/g) || []).length;
    return s.length > 0 ? digits / s.length : 0;
  }
  
  punycode() {
    return (this.url.startsWith('http://xn--') || this.url.startsWith('https://xn--')) ? 1 : 0;
  }
  
  port() {
    return /:[0-9]+/.test(this.parsed.hostname) ? 1 : 0;
  }
  
  tld_in_path() {
    return this.parsed.path.toLowerCase().includes(this.parsed.tld) ? 1 : 0;
  }
  
  tld_in_subdomain() {
    return this.parsed.subdomain.includes(this.parsed.tld) ? 1 : 0;
  }
  
  abnormal_subdomain() {
    return /^(http[s]?:\/\/(w[w]?|\d))([w]?(\d|-))/.test(this.url) ? 1 : 0;
  }
  
  count_subdomain() {
    const dots = (this.parsed.hostname.match(/\./g) || []).length;
    if (dots === 1) return 1;
    if (dots === 2) return 2;
    return 3;
  }
  
  prefix_suffix() {
    return /https?:\/\/[^-]+-[^-]+\//.test(this.url) ? 1 : 0;
  }
  
  random_domain() {
    // Simplified version - checks if domain has many consonants in a row
    const consonantPattern = /[bcdfghjklmnpqrstvwxyz]{4,}/i;
    return consonantPattern.test(this.parsed.domain) ? 1 : 0;
  }
  
  shortening_service() {
    const shorteners = /bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd/;
    return shorteners.test(this.url) ? 1 : 0;
  }
  
  path_extension() {
    return this.parsed.path.endsWith('.txt') ? 1 : 0;
  }
  
  count_redirection() {
    // Can't detect HTTP redirects in browser extension, return 0
    return 0;
  }
  
  count_external_redirection() {
    return 0;
  }
  
  length_word_raw() {
    return this.parsed.words_raw.length;
  }
  
  char_repeat() {
    let count = 0;
    for (const word of this.parsed.words_raw) {
      for (let len = 2; len <= 5; len++) {
        for (let i = 0; i <= word.length - len; i++) {
          const substr = word.substring(i, i + len);
          if (new Set(substr).size === 1) {
            count++;
          }
        }
      }
    }
    return count;
  }
  
  shortest_word_length(words) {
    return words.length > 0 ? Math.min(...words.map(w => w.length)) : 0;
  }
  
  longest_word_length(words) {
    return words.length > 0 ? Math.max(...words.map(w => w.length)) : 0;
  }
  
  average_word_length(words) {
    if (words.length === 0) return 0;
    const total = words.reduce((sum, w) => sum + w.length, 0);
    return total / words.length;
  }
  
  phish_hints() {
    let count = 0;
    const pathLower = this.parsed.path.toLowerCase();
    for (const hint of HINTS) {
      count += (pathLower.match(new RegExp(hint, 'g')) || []).length;
    }
    return count;
  }
  
  domain_in_brand() {
    return BRANDS.includes(this.parsed.domain.toLowerCase()) ? 1 : 0;
  }
  
  brand_in_subdomain() {
    const subLower = this.parsed.subdomain.toLowerCase();
    for (const brand of BRANDS) {
      if (subLower.includes(brand) && !this.parsed.domain.toLowerCase().includes(brand)) {
        return 1;
      }
    }
    return 0;
  }
  
  brand_in_path() {
    const pathLower = this.parsed.path.toLowerCase();
    for (const brand of BRANDS) {
      if (pathLower.includes(`.${brand}.`) && !this.parsed.domain.toLowerCase().includes(brand)) {
        return 1;
      }
    }
    return 0;
  }
  
  suspecious_tld() {
    return SUSPICIOUS_TLDS.includes(this.parsed.tld) ? 1 : 0;
  }
  
  statistical_report() {
    // Simplified - checks against known malicious patterns
    const suspicious = /146\.112\.61\.108|213\.174\.157\.151|at\.ua|usa\.cc/;
    return suspicious.test(this.url) ? 1 : 0;
  }

  // Content-based features (require DOM)
  nb_hyperlinks() {
    if (!this.dom) return 0;
    const hrefs = this.dom.querySelectorAll('[href]').length;
    const srcs = this.dom.querySelectorAll('[src]').length;
    return hrefs + srcs;
  }

  internal_hyperlinks() {
    if (!this.dom) return 0;
    let internal = 0, total = 0;
    this.dom.querySelectorAll('[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href) {
        total++;
        if (href.includes(this.parsed.domain) || href.startsWith('/')) internal++;
      }
    });
    return total > 0 ? internal / total : 0;
  }

  external_hyperlinks() {
    return 1 - this.internal_hyperlinks();
  }

  null_hyperlinks() {
    if (!this.dom) return 0;
    let nullCount = 0, total = 0;
    const nullFormats = ['', '#', '#nothing', 'javascript:void(0)', 'javascript:;'];
    this.dom.querySelectorAll('[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href) {
        total++;
        if (nullFormats.includes(href.trim())) nullCount++;
      }
    });
    return total > 0 ? nullCount / total : 0;
  }

  external_css() {
    if (!this.dom) return 0;
    let count = 0;
    this.dom.querySelectorAll('link[rel="stylesheet"]').forEach(el => {
      const href = el.getAttribute('href');
      if (href && !href.includes(this.parsed.domain) && href.startsWith('http')) {
        count++;
      }
    });
    return count;
  }

  login_form() {
    if (!this.dom) return 0;
    const forms = this.dom.querySelectorAll('form');
    for (const form of forms) {
      const inputs = form.querySelectorAll('input[type="password"]');
      if (inputs.length > 0) return 1;
    }
    return 0;
  }

  external_favicon() {
    if (!this.dom) return 0;
    const favicons = this.dom.querySelectorAll('link[rel*="icon"]');
    for (const fav of favicons) {
      const href = fav.getAttribute('href');
      if (href && href.startsWith('http') && !href.includes(this.parsed.domain)) {
        return 1;
      }
    }
    return 0;
  }

  links_in_tags() {
    if (!this.dom) return 0;
    let internal = 0, total = 0;
    this.dom.querySelectorAll('link[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href) {
        total++;
        if (href.includes(this.parsed.domain) || href.startsWith('/')) internal++;
      }
    });
    return total > 0 ? internal / total : 0;
  }

  submitting_to_email() {
    if (!this.dom) return 0;
    const forms = this.dom.querySelectorAll('form[action]');
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (action && (action.includes('mailto:') || action.includes('mail()'))) {
        return 1;
      }
    }
    return 0;
  }

  internal_media() {
    if (!this.dom) return 0;
    let internal = 0, total = 0;
    this.dom.querySelectorAll('img[src], audio[src], video[src]').forEach(el => {
      const src = el.getAttribute('src');
      if (src) {
        total++;
        if (src.includes(this.parsed.domain) || src.startsWith('/')) internal++;
      }
    });
    return total > 0 ? (internal / total) * 100 : 0;
  }

  external_media() {
    if (!this.dom) return 0;
    return 100 - this.internal_media();
  }

  sfh() {
    if (!this.dom) return 0;
    const forms = this.dom.querySelectorAll('form');
    for (const form of forms) {
      const action = form.getAttribute('action');
      if (!action || action === '' || action === 'about:blank') return 1;
    }
    return 0;
  }

  iframe() {
    if (!this.dom) return 0;
    const iframes = this.dom.querySelectorAll('iframe[width="0"][height="0"]');
    return iframes.length > 0 ? 1 : 0;
  }

  popup_window() {
    if (!this.dom) return 0;
    const html = this.dom.documentElement.outerHTML;
    return html.toLowerCase().includes('prompt(') ? 1 : 0;
  }

  safe_anchor() {
    if (!this.dom) return 0;
    let unsafe = 0, total = 0;
    this.dom.querySelectorAll('a[href]').forEach(el => {
      const href = el.getAttribute('href');
      if (href) {
        total++;
        if (href.includes('#') || href.includes('javascript') || href.includes('mailto')) {
          unsafe++;
        }
      }
    });
    return total > 0 ? (unsafe / total) * 100 : 0;
  }

  onmouseover() {
    if (!this.dom) return 0;
    const html = this.dom.documentElement.outerHTML;
    return /onmouseover\s*=\s*["']window\.status/i.test(html) ? 1 : 0;
  }

  right_clic() {
    if (!this.dom) return 0;
    const html = this.dom.documentElement.outerHTML;
    return /event\.button\s*==\s*2/.test(html) ? 1 : 0;
  }

  empty_title() {
    if (!this.dom) return 0;
    const title = this.dom.querySelector('title');
    return (!title || !title.textContent.trim()) ? 1 : 0;
  }

  domain_in_title() {
    if (!this.dom) return 0;
    const title = this.dom.querySelector('title');
    if (!title) return 1;
    return title.textContent.toLowerCase().includes(this.parsed.domain.toLowerCase()) ? 0 : 1;
  }

  domain_with_copyright() {
    if (!this.dom) return 0;
    const html = this.dom.documentElement.outerHTML;
    const copyrightMatch = html.match(/[Â©Â®â„¢]/);
    if (!copyrightMatch) return 0;
    
    const idx = copyrightMatch.index;
    const context = html.substring(Math.max(0, idx - 50), Math.min(html.length, idx + 50));
    return context.toLowerCase().includes(this.parsed.domain.toLowerCase()) ? 0 : 1;
  }

  // Extract all features in correct order
  extractFeatures() {
    if (!this.parsed) return null;

    const features = [
      this.url_length(this.url),
      this.url_length(this.parsed.hostname),
      this.having_ip_address(),
      this.count_dots(),
      this.count_hyphens(),
      this.count_at(),
      this.count_exclamation(),
      this.count_and(),
      this.count_or(),
      this.count_equal(),
      this.count_underscore(),
      this.count_tilde(),
      this.count_percentage(),
      this.count_slash(),
      this.count_star(),
      this.count_colon(),
      this.count_comma(),
      this.count_semicolumn(),
      this.count_dollar(),
      this.count_space(),
      this.check_www(),
      this.check_com(),
      this.count_double_slash(),
      this.count_http_token(),
      this.https_token(),
      this.ratio_digits(this.url),
      this.ratio_digits(this.parsed.hostname),
      this.punycode(),
      this.port(),
      this.tld_in_path(),
      this.tld_in_subdomain(),
      this.abnormal_subdomain(),
      this.count_subdomain(),
      this.prefix_suffix(),
      this.random_domain(),
      this.shortening_service(),
      this.path_extension(),
      this.count_redirection(),
      this.count_external_redirection(),
      this.length_word_raw(),
      this.char_repeat(),
      this.shortest_word_length(this.parsed.words_raw),
      this.shortest_word_length(this.parsed.words_raw_host),
      this.shortest_word_length(this.parsed.words_raw_path),
      this.longest_word_length(this.parsed.words_raw),
      this.longest_word_length(this.parsed.words_raw_host),
      this.longest_word_length(this.parsed.words_raw_path),
      this.average_word_length(this.parsed.words_raw),
      this.average_word_length(this.parsed.words_raw_host),
      this.average_word_length(this.parsed.words_raw_path),
      this.phish_hints(),
      this.domain_in_brand(),
      this.brand_in_subdomain(),
      this.brand_in_path(),
      this.suspecious_tld(),
      this.statistical_report(),
      this.nb_hyperlinks(),
      this.internal_hyperlinks(),
      this.external_hyperlinks(),
      this.null_hyperlinks(),
      this.external_css(),
      0, // internal_redirection (requires HTTP requests)
      0, // external_redirection
      0, // internal_errors
      0, // external_errors
      this.login_form(),
      this.external_favicon(),
      this.links_in_tags(),
      this.submitting_to_email(),
      this.internal_media(),
      this.external_media(),
      this.sfh(),
      this.iframe(),
      this.popup_window(),
      this.safe_anchor(),
      this.onmouseover(),
      this.right_clic(),
      this.empty_title(),
      this.domain_in_title(),
      this.domain_with_copyright()
    ];

    return features;
  }
}

// Make available globally
if (typeof module !== 'undefined' && module.exports) {
  module.exports = FeatureExtractor;
}