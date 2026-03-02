/**
 * Access Controller
 * 
 * Origin-based allowlisting: which browser origins
 * can access which backend services through the proxy.
 */

function createAccessController(config) {
  const rules = config.access || [];

  function isAllowed(origin, serviceName) {
    // No rules = allow all (open mode for development)
    if (rules.length === 0) return true;

    // Clean origin
    const cleanOrigin = origin ? origin.replace(/\/$/, '') : '';

    for (const rule of rules) {
      if (matchOrigin(cleanOrigin, rule.origin)) {
        if (rule.allow.includes('*') || rule.allow.includes(serviceName)) {
          return true;
        }
      }
    }

    return false;
  }

  function matchOrigin(origin, pattern) {
    if (pattern === '*') return true;
    if (!origin) return false;

    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(origin);
    }

    return origin === pattern;
  }

  function listRules() {
    return rules;
  }

  return { isAllowed, listRules };
}

module.exports = { createAccessController };
