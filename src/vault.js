/**
 * Key Vault
 * 
 * Manages API keys for external services.
 * Keys are loaded from config and injected into proxied requests.
 * 
 * Future: encrypted at-rest storage, key rotation, etc.
 */

async function createKeyVault(config) {
  const services = new Map();

  // Load services from config
  if (config.keys) {
    for (const [name, service] of Object.entries(config.keys)) {
      services.set(name, {
        header: service.header || 'Authorization',
        value: service.value,
        base_url: service.base_url,
      });
    }
  }

  function getService(name) {
    return services.get(name) || null;
  }

  function listServices() {
    return Array.from(services.keys());
  }

  function addService(name, service) {
    services.set(name, service);
  }

  function removeService(name) {
    return services.delete(name);
  }

  return { getService, listServices, addService, removeService };
}

module.exports = { createKeyVault };
