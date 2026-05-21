export const environment = {
  production: false,
  // Real Docker services configuration (browser connects via static IPs)
  apiUrl: 'http://localhost:8082/api',
  wsUrl: 'ws://localhost:8082/ws',
  // API key for authenticated routes (leave empty to disable)
  apiKey: '',
  logProcessorUrl: 'http://172.20.0.13:8095', // Log processor service
  networkFilterUrl: 'http://localhost:8082/api/prevention',
  suricataStatusUrl: 'http://localhost:8082/api/status',
  
  // Service endpoints for Docker containers
  services: {
    suricata: {
      name: 'suricata-vps',
      status: 'running' // Suricata runs on host network
    },
    mockApi: {
      name: 'idps-api-gateway',
      port: 8080
    },
    logProcessor: {
      name: 'idps-log-processor', 
      port: 8095
    },
    mongo: {
      name: 'idps-mongo',
      port: 27017
    }
  }
};
