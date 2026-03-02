/**
 * Request Logger
 * 
 * Structured logging for all proxy activity.
 * Audit trail of what went where.
 */

function createLogger(config) {
  const level = config.log_level || 'info';
  const levels = { error: 0, warn: 1, info: 2, debug: 3 };
  const currentLevel = levels[level] ?? 2;

  function log(lvl, msg) {
    if (levels[lvl] <= currentLevel) {
      const timestamp = new Date().toISOString();
      const prefix = lvl === 'error' ? '❌' : lvl === 'warn' ? '⚠️' : lvl === 'debug' ? '🔍' : '→';
      console.log(`[${timestamp}] ${prefix} ${msg}`);
    }
  }

  return {
    error: (msg) => log('error', msg),
    warn: (msg) => log('warn', msg),
    info: (msg) => log('info', msg),
    debug: (msg) => log('debug', msg),
  };
}

module.exports = { createLogger };
