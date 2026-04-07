import dns from 'node:dns/promises';

const BLOCKED_HOSTS = new Set([
  '169.254.169.254',       // AWS metadata
  'metadata.google.internal', // GCP metadata
  'metadata.google',
  'localhost',
]);

const PRIVATE_RANGES = [
  /^127\./,              // loopback
  /^10\./,               // class A private
  /^172\.(1[6-9]|2\d|3[01])\./,  // class B private
  /^192\.168\./,         // class C private
  /^0\./,                // current network
  /^169\.254\./,         // link-local
  /^::1$/,               // IPv6 loopback
  /^fc00:/,              // IPv6 private
  /^fe80:/,              // IPv6 link-local
];

function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some((r) => r.test(ip));
}

/**
 * Validação anti-SSRF Layer 2: resolve DNS e verifica se IP é privado.
 * Protege contra DNS rebinding attacks.
 */
export async function validateUrlDNS(
  rawUrl: string
): Promise<{ valid: boolean; reason?: string }> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { valid: false, reason: 'Invalid URL' };
  }

  // Protocol check
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    return { valid: false, reason: `Protocol not allowed: ${parsed.protocol}` };
  }

  // Blocked hosts
  if (BLOCKED_HOSTS.has(parsed.hostname)) {
    return { valid: false, reason: `Blocked host: ${parsed.hostname}` };
  }

  // If it's already an IP, check directly
  const ipMatch = /^(\d{1,3}\.){3}\d{1,3}$/.test(parsed.hostname);
  if (ipMatch) {
    if (isPrivateIP(parsed.hostname)) {
      return { valid: false, reason: `Private IP: ${parsed.hostname}` };
    }
    return { valid: true };
  }

  // Resolve DNS
  try {
    const addresses = await dns.resolve4(parsed.hostname);
    for (const addr of addresses) {
      if (isPrivateIP(addr)) {
        return {
          valid: false,
          reason: `DNS resolves to private IP: ${addr} (hostname: ${parsed.hostname})`,
        };
      }
    }
  } catch (err: any) {
    return { valid: false, reason: `DNS resolution failed: ${err.message}` };
  }

  return { valid: true };
}
