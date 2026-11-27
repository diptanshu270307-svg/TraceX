/**
 * TraceX Email Threat Sentinel — Cloud Configuration
 * Defines live AWS backend endpoints and local development fallbacks.
 */

const TRACEX_CONFIG = {
  // AWS Cloud Hosted Endpoints (ap-south-1 EC2 Instance)
  AWS_GATEWAY_URL: "http://13.200.242.110:8000",
  AWS_GATEWAY_HTTP: "http://13.200.242.110",
  AWS_DNS_URL: "http://ec2-13-200-242-110.ap-south-1.compute.amazonaws.com:8000",

  // Localhost Development Endpoints
  LOCAL_GATEWAY_URL: "http://127.0.0.1:8000",
  LOCAL_GATEWAY_FALLBACK: "http://localhost:8000",

  // Playwright Detonation Sandbox Endpoints
  SANDBOX_URL: "http://13.200.242.110:8002",
  LOCAL_SANDBOX_URL: "http://127.0.0.1:8002",

  // S3 Cloud Evidence Vault
  S3_VAULT_BUCKET: "tracex-forensic-vault-diptanshu",
  S3_REGION: "ap-south-1",

  // Default mode: "LOCAL_FIRST" (tries local first, falls back to AWS)
  ACTIVE_MODE: "LOCAL_FIRST"
};

// Export for service worker and content script contexts
if (typeof self !== "undefined") {
  self.TRACEX_CONFIG = TRACEX_CONFIG;
}
if (typeof window !== "undefined") {
  window.TRACEX_CONFIG = TRACEX_CONFIG;
}
