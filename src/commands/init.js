/**
 * warden init - Initialize config directory
 */

const fs = require('node:fs');
const path = require('node:path');
const { getConfigDir, DEFAULT_CONFIG } = require('../config');

module.exports = async function init() {
  const configDir = getConfigDir();
  const configFile = path.join(configDir, 'config.yaml');

  // Create directory
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
    console.log(`✅ Created ${configDir}`);
  }

  // Create default config (JSON format for v0.1)
  if (!fs.existsSync(configFile)) {
    const defaultConfig = {
      port: 7400,
      log_level: "info",
      keys: {
        openai: {
          header: "Authorization",
          value: "Bearer ${OPENAI_API_KEY}",
          base_url: "https://api.openai.com"
        },
        anthropic: {
          header: "x-api-key",
          value: "${ANTHROPIC_API_KEY}",
          base_url: "https://api.anthropic.com"
        }
      },
      access: [
        {
          origin: "http://localhost:*",
          allow: ["openai", "anthropic"]
        }
      ],
      limits: {
        openai: { rpm: 60, rpd: 1000 },
        anthropic: { rpm: 30, rpd: 500 }
      }
    };

    fs.writeFileSync(configFile, JSON.stringify(defaultConfig, null, 2));
    console.log(`✅ Created ${configFile}`);
  } else {
    console.log(`ℹ️  Config already exists at ${configFile}`);
  }

  console.log(`\n🔒 Warden initialized!`);
  console.log(`\nNext steps:`);
  console.log(`  1. Edit ${configFile} with your API keys`);
  console.log(`  2. Set environment variables (OPENAI_API_KEY, etc.)`);
  console.log(`  3. Run: warden start`);
};
