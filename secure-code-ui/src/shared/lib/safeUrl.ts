// secure-code-ui/src/shared/lib/safeUrl.ts
//
// URL-scheme allowlist for any rendered link that comes from
// attacker-controlled sources (today: CycloneDX `externalReferences`
// in Scan.bom_cyclonedx). Rejects `javascript:`, `data:`, `vbscript:`,
// `file:` etc; allows http(s) and protocol-relative `//`. ADR-009 / G8.

const SAFE_PROTOCOLS = new Set(["http:", "https:"]);

export function isSafeHttpUrl(raw: unknown): boolean {
  if (typeof raw !== "string" || !raw) return false;
  // Allow protocol-relative URLs (e.g. `//example.com/x`).
  if (raw.startsWith("//")) return true;
  try {
    const u = new URL(raw);
    return SAFE_PROTOCOLS.has(u.protocol);
  } catch {
    return false;
  }
}
