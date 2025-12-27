// offpage.js
// Off-page RDAP-based domain risk analysis

async function fetchRDAP(domain) {
  const urls = [
    `https://rdap.org/domain/${domain}`,
    `https://icann.rdap.org/domain/${domain}`
  ];

  for (const url of urls) {
    try {
      const res = await fetch(url);
      if (res.ok) {
        return await res.json();
      }
    } catch (_) {
      // try next endpoint
    }
  }
  return null;
}

function calculateDomainRisk(data) {
  const domain = (data.ldhName || "").toLowerCase();
  
  const now = new Date();
  
  const events = Array.isArray(data.events) ? data.events : [];

  const createdStr =
    events.find((e) => e.eventAction === "registration")?.eventDate || null;
  const expiryStr =
    events.find((e) => e.eventAction === "expiration")?.eventDate || null;
  const updatedStr =
    events.find((e) => e.eventAction === "last changed")?.eventDate || null;

  const created = createdStr ? new Date(createdStr) : null;
  const expires = expiryStr ? new Date(expiryStr) : null;
  const updated = updatedStr ? new Date(updatedStr) : null;

  const msPerDay = 1000 * 60 * 60 * 24;

  const daysAge = created ? Math.floor((now - created) / msPerDay) : null;
  const daysLifespan =
    created && expires ? Math.floor((expires - created) / msPerDay) : null;
  const daysSinceUpdate = updated ? Math.floor((now - updated) / msPerDay) : null;

  let scoreAge = 0;
  let scoreLifespan = 0;
  let scoreUpdate = 0;

  // Whitelist check - calculate scores but override to 0 for regulated domains
  const isWhitelisted = domain.endsWith('.bank.in') || domain.endsWith('.gov.in');

  if (!isWhitelisted) {
    // Normal scoring
    if (daysAge !== null) {
      if (daysAge <= 30) scoreAge = 50;
      else if (daysAge <= 180) scoreAge = 35;
      else if (daysAge <= 365) scoreAge = 25;
      else if (daysAge <= 1095) scoreAge = 10;
      else if (daysAge <= 3650) scoreAge = 5;
      else scoreAge = 2;
    }

    if (daysLifespan !== null) {
      if (daysLifespan <= 365) scoreLifespan = 30;
      else if (daysLifespan <= 730) scoreLifespan = 15;
      else if (daysLifespan <= 1825) scoreLifespan = 5;
      else scoreLifespan = 0;
    }

    if (daysAge !== null && daysSinceUpdate !== null) {
      if (daysSinceUpdate <= 7 && daysAge <= 60) scoreUpdate = 20;
      else if (daysSinceUpdate <= 30 && daysAge > 365) scoreUpdate = 10;
    }
  }

  const rawScore = scoreAge + scoreLifespan + scoreUpdate;
  const normalized = Math.min(1, rawScore / 100);

  return {
    domain: domain,
    daysAge,
    daysLifespan,
    daysSinceUpdate,
    scoreAge,
    scoreLifespan,
    scoreUpdate,
    rawScore,
    normalized,
    whitelisted: isWhitelisted
  };
}

export async function analyzeDomain(domain) {
  const rdapData = await fetchRDAP(domain);
  if (!rdapData) {
    return { error: true, reason: "RDAP lookup failed" };
  }
  try {
    return calculateDomainRisk(rdapData);
  } catch (e) {
    return { error: true, reason: "RDAP parse error" };
  }
}