/**
 * Logo Detection Heuristic
 *
 * Scans the DOM for likely logo elements and returns their bounding box.
 * Intended to run in a content script (needs DOM access).
 *
 * Scoring:
 *  - +10 if id/class/alt/src contain logo|brand|header|nav
 *  - +20 if element is within the top 150px of the page
 *  - +15 if wrapped in an <a> that points to root ("/" or same-domain root)
 *
 * Exclusions:
 *  - width < 20px (too small / favicon size)
 *  - width > 600px (likely hero/banner)
 *  - height > 200px (likely hero/banner)
 *
 * Returns:
 *  - { x, y, width, height, score } for the highest scoring element above threshold
 *  - null if no candidate scores >= MIN_SCORE
 */

const MIN_SCORE = 20;
const KEYWORD_SCORE = 10;
const TOP_SCORE = 20;
const LINK_SCORE = 15;
const TOP_BOUNDARY = 150; // px
const MIN_WIDTH = 20;
const MAX_WIDTH = 600;
const MAX_HEIGHT = 200;

const KEYWORDS = ['logo', 'brand', 'header', 'nav'];

function matchesKeywords(str = '') {
  const lower = str.toLowerCase();
  return KEYWORDS.some((kw) => lower.includes(kw));
}

function isRootLink(anchor, currentDomain) {
  if (!anchor || !anchor.href) return false;
  try {
    const url = new URL(anchor.href, window.location.href);
    if (url.origin !== window.location.origin) return false;
    // root paths: "/", "", or just origin
    if (url.pathname === '/' || url.pathname === '' || url.href === window.location.origin + '/') {
      return true;
    }
    // allow anchors pointing to same origin root with fragments/queries
    if (url.pathname === '/' && (url.search || url.hash)) {
      return true;
    }
    // If a currentDomain is provided, allow links to that domain's root
    if (currentDomain && url.hostname === currentDomain && url.pathname === '/') {
      return true;
    }
  } catch (e) {
    return false;
  }
  return false;
}

function getBackgroundImageCandidates() {
  const nodes = Array.from(document.querySelectorAll('*'));
  return nodes.filter((el) => {
    const style = getComputedStyle(el);
    const bg = style.backgroundImage;
    if (!bg || bg === 'none') return false;
    // Skip gradients
    if (bg.includes('gradient')) return false;
    return true;
  });
}

function elementScore(el, currentDomain) {
  if (!el || typeof el.getBoundingClientRect !== 'function') return -Infinity;

  const rect = el.getBoundingClientRect();
  const width = rect.width;
  const height = rect.height;

  // Size exclusions
  if (width < MIN_WIDTH || width > MAX_WIDTH) return -Infinity;
  if (height > MAX_HEIGHT) return -Infinity;

  let score = 0;

  // Keywords in id/class/alt/src
  const idClass = `${el.id || ''} ${el.className || ''}`;
  const alt = el.alt || '';
  const src = el.src || '';
  if (matchesKeywords(idClass) || matchesKeywords(alt) || matchesKeywords(src)) {
    score += KEYWORD_SCORE;
  }

  // Position bonus: near top
  if (rect.top >= 0 && rect.top <= TOP_BOUNDARY) {
    score += TOP_SCORE;
  }

  // Link parent bonus
  const anchor = el.closest('a');
  if (isRootLink(anchor, currentDomain)) {
    score += LINK_SCORE;
  }

  return score;
}

export function findLogoCoordinates(currentDomain = window.location.hostname) {
  const candidates = [];

  // <img> elements
  candidates.push(...Array.from(document.images));

  // <svg> elements
  candidates.push(...Array.from(document.querySelectorAll('svg')));

  // Elements with background images
  candidates.push(...getBackgroundImageCandidates());

  let best = null;
  let bestScore = -Infinity;

  for (const el of candidates) {
    const score = elementScore(el, currentDomain);
    if (score > bestScore) {
      bestScore = score;
      best = el;
    }
  }

  if (!best || bestScore < MIN_SCORE) {
    return null;
  }

  const rect = best.getBoundingClientRect();
  return {
    x: rect.x,
    y: rect.y,
    width: rect.width,
    height: rect.height,
    score: bestScore
  };
}

