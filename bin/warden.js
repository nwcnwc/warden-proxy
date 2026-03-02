#!/usr/bin/env node

/**
 * Warden CLI
 * 
 * Commands:
 *   warden init          - Initialize config directory (~/.warden/)
 *   warden start         - Start the proxy server
 *   warden stop          - Stop the proxy server
 *   warden add-key       - Add an API key
 *   warden remove-key    - Remove an API key
 *   warden allow         - Allow an origin to access a service
 *   warden deny          - Remove an origin's access to a service
 *   warden status        - Show proxy status and config summary
 *   warden log           - Tail the request log
 */

const { parseArgs } = require('node:util');
const path = require('node:path');

const commands = {
  init: () => require('../src/commands/init')(),
  start: () => require('../src/commands/start')(),
  stop: () => require('../src/commands/stop')(),
  'add-key': () => require('../src/commands/add-key')(),
  'remove-key': () => require('../src/commands/remove-key')(),
  allow: () => require('../src/commands/allow')(),
  deny: () => require('../src/commands/deny')(),
  status: () => require('../src/commands/status')(),
  log: () => require('../src/commands/log')(),
};

const command = process.argv[2];

if (!command || command === '--help' || command === '-h') {
  console.log(`
🔒 Warden Proxy - Safe external access for browser applications

Usage: warden <command> [options]

Commands:
  init                Initialize config directory (~/.warden/)
  start               Start the proxy server
  stop                Stop the proxy server
  add-key <name>      Add an API key
  remove-key <name>   Remove an API key  
  allow <origin> <service>   Allow an origin to access a service
  deny <origin> <service>    Remove access
  status              Show proxy status
  log                 Tail the request log

Options:
  -h, --help          Show this help
  -v, --version       Show version

Examples:
  warden init
  warden add-key openai
  warden allow http://localhost:3000 openai
  warden start
`);
  process.exit(0);
}

if (command === '--version' || command === '-v') {
  const pkg = require('../package.json');
  console.log(pkg.version);
  process.exit(0);
}

if (!commands[command]) {
  console.error(`Unknown command: ${command}`);
  console.error('Run "warden --help" for usage');
  process.exit(1);
}

commands[command]().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
