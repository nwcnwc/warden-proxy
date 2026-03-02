/**
 * warden status - Show proxy status
 */

const http = require('node:http');

module.exports = async function status() {
  try {
    const data = await new Promise((resolve, reject) => {
      http.get('http://127.0.0.1:7400/status', (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => resolve(JSON.parse(body)));
      }).on('error', reject);
    });

    console.log('🔒 Warden Proxy Status\n');
    console.log(`Uptime: ${Math.round(data.uptime)}s`);
    console.log(`Services: ${data.services.join(', ') || 'none'}`);
    console.log(`\nAccess Rules:`);
    for (const rule of data.access) {
      console.log(`  ${rule.origin} → ${rule.allow.join(', ')}`);
    }
    if (Object.keys(data.limits).length > 0) {
      console.log(`\nRate Limits:`);
      for (const [service, info] of Object.entries(data.limits)) {
        console.log(`  ${service}: ${info.usage.last_minute}/${info.limits.rpm || '∞'} rpm, ${info.usage.last_day}/${info.limits.rpd || '∞'} rpd`);
      }
    }
  } catch {
    console.log('⚠️  Warden Proxy is not running');
    console.log('   Start it with: warden start');
  }
};
