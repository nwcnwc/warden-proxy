/**
 * Rate Limiter
 * 
 * Per-service rate limiting to prevent runaway costs.
 * Uses sliding window counters.
 */

function createRateLimiter(config) {
  const limits = config.limits || {};
  const counters = new Map(); // service -> { minute: [], day: [] }

  function check(serviceName) {
    const serviceLimit = limits[serviceName];
    if (!serviceLimit) return true; // No limits configured

    const now = Date.now();
    if (!counters.has(serviceName)) {
      counters.set(serviceName, { requests: [] });
    }

    const counter = counters.get(serviceName);

    // Clean old entries
    counter.requests = counter.requests.filter(t => t > now - 86400000);

    // Check per-minute limit
    if (serviceLimit.rpm) {
      const minuteCount = counter.requests.filter(t => t > now - 60000).length;
      if (minuteCount >= serviceLimit.rpm) return false;
    }

    // Check per-day limit
    if (serviceLimit.rpd) {
      if (counter.requests.length >= serviceLimit.rpd) return false;
    }

    // Record this request
    counter.requests.push(now);
    return true;
  }

  function getStatus() {
    const now = Date.now();
    const status = {};

    for (const [service, limit] of Object.entries(limits)) {
      const counter = counters.get(service);
      const requests = counter ? counter.requests : [];

      status[service] = {
        limits: limit,
        usage: {
          last_minute: requests.filter(t => t > now - 60000).length,
          last_day: requests.filter(t => t > now - 86400000).length,
        },
      };
    }

    return status;
  }

  return { check, getStatus };
}

module.exports = { createRateLimiter };
