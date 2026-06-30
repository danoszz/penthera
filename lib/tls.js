/**
 * TLS/SSL Scanner
 *
 * Checks certificate validity, cipher strength, and protocol version
 * using Node.js built-in `tls` module — zero dependencies.
 *
 * Inspired by: httpx (JARM fingerprinting), testssl.sh, ssl-labs
 */
import tls from "node:tls";

const WEAK_CIPHERS = new Set([
  "DES-CBC3-SHA", "RC4-SHA", "RC4-MD5", "DES-CBC-SHA",
  "EXP-RC4-MD5", "EXP-DES-CBC-SHA", "EXP-RC2-CBC-MD5",
  "NULL-MD5", "NULL-SHA", "NULL-SHA256",
]);

const WEAK_PROTOCOLS = new Set(["TLSv1", "TLSv1.1", "SSLv3"]);

/**
 * Check TLS configuration for a hostname.
 *
 * @param {string} hostname - Target hostname (no protocol)
 * @param {number} port - Target port (default: 443)
 * @param {number} timeout - Connection timeout in ms
 * @returns {object} TLS scan result
 */
export function checkTls(hostname, port = 443, timeout = 10_000) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        const authError = socket.authorizationError || null;
        socket.end();

        const now = new Date();
        const validFrom = new Date(cert.valid_from);
        const validTo = new Date(cert.valid_to);
        const daysUntilExpiry = Math.floor((validTo - now) / 86400000);

        // Extract SAN (Subject Alternative Names)
        const altNames = cert.subjectaltname
          ? cert.subjectaltname.split(", ").map((s) => s.replace("DNS:", ""))
          : [];

        // Determine findings
        const findings = [];

        if (!authorized) {
          findings.push({
            severity: "high",
            title: "TLS certificate not trusted",
            description: authError || "Certificate validation failed",
          });
        }

        if (daysUntilExpiry < 0) {
          findings.push({
            severity: "critical",
            title: "TLS certificate expired",
            description: `Expired ${Math.abs(daysUntilExpiry)} days ago (${validTo.toISOString().slice(0, 10)})`,
          });
        } else if (daysUntilExpiry < 30) {
          findings.push({
            severity: "medium",
            title: "TLS certificate expiring soon",
            description: `Expires in ${daysUntilExpiry} days (${validTo.toISOString().slice(0, 10)})`,
          });
        }

        if (WEAK_PROTOCOLS.has(protocol)) {
          findings.push({
            severity: "high",
            title: `Weak TLS protocol: ${protocol}`,
            description: "TLSv1.0 and TLSv1.1 are deprecated. Use TLSv1.2 or TLSv1.3.",
          });
        }

        if (WEAK_CIPHERS.has(cipher?.name)) {
          findings.push({
            severity: "high",
            title: `Weak cipher suite: ${cipher.name}`,
            description: "This cipher is considered insecure.",
          });
        }

        if (cipher?.name && !cipher.name.includes("GCM") && !cipher.name.includes("CHACHA")) {
          findings.push({
            severity: "low",
            title: `Non-AEAD cipher: ${cipher.name}`,
            description: "Consider using AEAD ciphers (GCM, ChaCha20-Poly1305) for better security.",
          });
        }

        resolve({
          valid: authorized,
          protocol,
          cipher: cipher?.name || "unknown",
          cipherVersion: cipher?.version || "unknown",
          issuer: cert.issuer?.O || cert.issuer?.CN || "unknown",
          subject: cert.subject?.CN || "unknown",
          altNames,
          validFrom: validFrom.toISOString(),
          validTo: validTo.toISOString(),
          daysUntilExpiry,
          serialNumber: cert.serialNumber,
          fingerprint256: cert.fingerprint256,
          findings,
        });
      },
    );

    socket.setTimeout(timeout);
    socket.on("timeout", () => {
      socket.destroy();
      resolve({
        valid: false,
        protocol: null,
        cipher: null,
        error: "Connection timeout",
        findings: [{
          severity: "medium",
          title: "TLS connection timeout",
          description: `Could not establish TLS connection within ${timeout}ms`,
        }],
      });
    });
    socket.on("error", (err) => {
      resolve({
        valid: false,
        protocol: null,
        cipher: null,
        error: err.message,
        findings: [{
          severity: "medium",
          title: "TLS connection failed",
          description: err.message,
        }],
      });
    });
  });
}
