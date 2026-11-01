/**
 * Bot-protection challenges. A CDN firewall that challenges the scanner answers
 * every request with its own interstitial (HTTP 403, no app headers), so a scan
 * that keeps going measures the challenge page, not the site: "missing CSP",
 * "no login rate limiting" and so on, all false.
 */

/**
 * The challenge a response's headers announce, or null.
 * @param {Record<string, string> | Headers | null | undefined} headers
 * @returns {{ provider: string, action: string } | null}
 */
export function botChallenge(headers) {
  if (!headers) return null;
  const get = (name) => String((typeof headers.get === "function" ? headers.get(name) : headers[name]) || "").toLowerCase();
  const vercel = get("x-vercel-mitigated");
  if (vercel === "challenge" || vercel === "deny") return { provider: "Vercel", action: vercel };
  if (get("cf-mitigated") === "challenge") return { provider: "Cloudflare", action: "challenge" };
  return null;
}

/**
 * A block page some vendors announce only in part. Unlike a challenge this is not
 * certain, so the scan goes on and says so. Only headers these vendors set count,
 * on the statuses they block with: a bare 403 could be the app's own.
 * @returns {object|null} an info finding
 */
export function blockWarning(status, headers, url) {
  const get = (name) => String(headers?.get?.(name) ?? "").toLowerCase();
  const vendor = get("x-amzn-waf-action") ? "AWS WAF"
    : status !== 403 ? null
      : get("server").startsWith("akamaighost") ? "Akamai"
        : get("server").startsWith("awselb") ? "AWS load balancer"
          : get("x-cache").startsWith("error from cloudfront") ? "CloudFront" : null;
  if (!vendor) return null;
  return {
    severity: "info",
    title: `${vendor} answered HTTP ${status}, so the site was probably not read`,
    description: `This may be ${vendor}'s block page, in which case the header and page checks describe it and not your site.`,
    url,
    category: "scan",
    source: "waf-challenge",
    confidence: "likely",
  };
}

/** The info finding a scan reports instead of results it could not measure. */
export function challengeFinding(challenge, url) {
  return {
    severity: "info",
    title: `${challenge.provider} served a bot challenge instead of the site`,
    description: `The firewall answered with its challenge page (${challenge.action}), so header, discovery and login checks were skipped: they would have measured that page, not your app. Wait a few minutes, allow this scanner in the firewall for your own scan, or scan a preview deployment.`,
    url,
    category: "scan",
    source: "waf-challenge",
    confidence: "confirmed",
  };
}
