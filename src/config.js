/**
 * Configuration loader
 * 
 * Reads from ~/.warden/config.yaml (or specified path)
 * Supports environment variable interpolation: ${VAR_NAME}
 */

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const DEFAULT_CONFIG_DIR = path.join(os.homedir(), '.warden');
const DEFAULT_CONFIG_FILE = path.join(DEFAULT_CONFIG_DIR, 'config.yaml');

const DEFAULT_CONFIG = {
  port: 7400,
  log_level: 'info',
  keys: {},
  access: [],
  limits: {},
  devices: {},
};

/**
 * Simple YAML-like parser for our config format
 * (Avoids external dependency for v0.1)
 */
function parseSimpleYaml(text) {
  // For v0.1, we use JSON config with .yaml extension
  // TODO: Add proper YAML parsing or switch to JSON
  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Config parse error. Currently using JSON format (YAML parser coming in v0.2)');
  }
}

/**
 * Interpolate environment variables in string values
 * ${VAR_NAME} -> process.env.VAR_NAME
 */
function interpolateEnv(obj) {
  if (typeof obj === 'string') {
    return obj.replace(/\$\{([^}]+)\}/g, (match, varName) => {
      const value = process.env[varName];
      if (value === undefined) {
        console.warn(`Warning: Environment variable ${varName} not set`);
        return match;
      }
      return value;
    });
  }
  if (Array.isArray(obj)) {
    return obj.map(interpolateEnv);
  }
  if (obj && typeof obj === 'object') {
    const result = {};
    for (const [key, value] of Object.entries(obj)) {
      result[key] = interpolateEnv(value);
    }
    return result;
  }
  return obj;
}

async function loadConfig(configPath) {
  const filePath = configPath || DEFAULT_CONFIG_FILE;

  if (!fs.existsSync(filePath)) {
    console.warn(`No config found at ${filePath}, using defaults`);
    return { ...DEFAULT_CONFIG, _path: filePath };
  }

  const raw = fs.readFileSync(filePath, 'utf-8');
  const parsed = parseSimpleYaml(raw);
  const config = interpolateEnv({ ...DEFAULT_CONFIG, ...parsed });
  config._path = filePath;

  return config;
}

function getConfigDir() {
  return DEFAULT_CONFIG_DIR;
}

module.exports = { loadConfig, getConfigDir, DEFAULT_CONFIG };
