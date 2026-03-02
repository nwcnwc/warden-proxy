/**
 * warden start - Start the proxy server
 */

const { start } = require('../index');

module.exports = async function startCommand() {
  console.log('🔒 Starting Warden Proxy...\n');
  await start();
};
