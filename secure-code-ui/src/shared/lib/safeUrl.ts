// secure-code-ui/src/shared/lib/safeUrl.ts
//
// URL-scheme allowlist for any rendered link that comes from
// attacker-controlled sources (today: CycloneDX `externalReferences`
// in Scan.bom_cyclonedx, OSV finding `references[]`). Rejects
// `javascript:`, `data:`, `vbscript:`, `file:` etc; allows http(s)
// and protocol-relative `//`. ADR-009 / G8.
//
// IMPORTANT — context restriction (Phase-9 follow-up):
// `isSafeHttpUrl` is safe ONLY for `<a href>` rendering. Protocol-
// relative URLs like `//evil.example.com/x` inherit the page's
// scheme (https in production), which is correct for anchor links
// but UNSAFE for:
//   - `<iframe src>`  (loads attacker content into the page DOM)
//   - `<script src>`  (executes attacker code)
//   - `<form action>` (submits credentials to attacker host)
//   - any `window.location` / `location.href` assignment
// For those contexts, the caller must additionally require an
// explicit `http:` or `https:` scheme (reject the `//` case) and
// validate the host against an allowlist.

const SAFE_PROTOCOLS = new Set(["http:", "https:"]);

export function isSafeHttpUrl(raw: unknown): boolean {
  if (typeof raw !== "string" || !raw) return false;
  // Allow protocol-relative URLs (e.g. `//example.com/x`). See module
  // header — only safe for `<a href>` rendering.
  if (raw.startsWith("//")) return true;
  try {
    const u = new URL(raw);
    return SAFE_PROTOCOLS.has(u.protocol);
  } catch {
    return false;
  }
}
