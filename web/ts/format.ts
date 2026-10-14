// Pure formatting helpers, shared with the server's conventions and tested
// with node --test (web/test/format.test.mjs).

const DAY_MS = 86_400_000;

// Whole days left until notAfter, truncated: 29 days and 23 hours is 29.
// Negative once the certificate has expired (an hour past expiry is -1).
export function daysLeft(notAfter: Date, now: Date): number {
  return Math.floor((notAfter.getTime() - now.getTime()) / DAY_MS);
}

// The first 8 hex characters of a fingerprint, lowercase, separators removed.
export function shortFingerprint(fp: string): string {
  return fp.replace(/[^0-9a-fA-F]/g, "").slice(0, 8).toLowerCase();
}

// AB:CD:EF… notation for a hex fingerprint.
export function formatFingerprint(fp: string): string {
  const hex = fp.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
  const pairs = hex.match(/.{1,2}/g);
  return pairs === null ? "" : pairs.join(":");
}

export const MAX_TAG_LENGTH = 40;

// Splits a tag field on commas and whitespace: lowercase, deduplicated, empty
// and over-long (more than 40 characters) tags dropped, order kept.
export function parseTags(s: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of s.split(/[\s,]+/)) {
    const tag = raw.trim().toLowerCase();
    if (tag === "" || tag.length > MAX_TAG_LENGTH || seen.has(tag)) continue;
    seen.add(tag);
    out.push(tag);
  }
  return out;
}

// Share of the validity period already used, 0 to 100, as an integer.
export function lifetimePercent(notBefore: Date, notAfter: Date, now: Date): number {
  const total = notAfter.getTime() - notBefore.getTime();
  if (total <= 0) return 100;
  const used = ((now.getTime() - notBefore.getTime()) / total) * 100;
  return Math.min(100, Math.max(0, Math.round(used)));
}
