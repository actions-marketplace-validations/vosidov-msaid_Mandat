// PII / secret redaction applied to tool arguments BEFORE they reach any log, ledger or approval message.

import { sha256 } from "../util.ts";

export interface RedactionOptions {
  /** Extra key names (case-insensitive substrings) whose values are always removed. */
  keys?: string[];
  /** Built-in string patterns to mask. Default: all. */
  patterns?: Array<"email" | "card" | "phone" | "iban" | "jwt" | "secret">;
  /** Explicit arg paths to replace with a hash ("customer.email"). */
  fields?: string[];
  /** Metadata-only mode: drop all values, keep keys + a hash per value. */
  metadataOnly?: boolean;
}

// Substring match on key names, plus short names that only match exactly (so "pinned" stays visible).
const SECRET_KEYS = ["password", "passwd", "secret", "token", "apikey", "api_key", "api-key", "authorization", "cookie", "private_key"];
const SECRET_KEYS_EXACT = ["pin", "cvv", "cvc", "ssn"];

const PATTERNS = {
  jwt: { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, fn: () => "[JWT]" },
  secret: { re: /\b(?:sk|pk|rk|xox[abpr]|ghp|gho|github_pat|AKIA)[-_A-Za-z0-9]{12,}\b/g, fn: () => "[SECRET]" },
  email: { re: /\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g, fn: (_: string, first: string, dom: string) => `${first}***@${dom}` },
  iban: { re: /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b/g, fn: () => "[IBAN]" },
  card: {
    re: /\b(?:\d[ -]?){13,19}\b/g,
    fn: (m: string) => {
      const d = m.replace(/\D/g, "");
      return luhn(d) ? `[CARD ****${d.slice(-4)}]` : m;
    },
  },
  phone: { re: /(?<![\w.])\+\d[\d\s().-]{8,16}\d\b/g, fn: () => "[PHONE]" },
} as const;

function luhn(d: string): boolean {
  if (d.length < 13 || d.length > 19) return false;
  let sum = 0;
  for (let i = 0; i < d.length; i++) {
    let n = Number(d[d.length - 1 - i]);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

export function hashValue(v: unknown): string {
  return "sha256:" + sha256(JSON.stringify(v) ?? "null").slice(0, 16);
}

export function redactString(s: string, patterns: RedactionOptions["patterns"]): string {
  let out = s;
  for (const name of patterns ?? (Object.keys(PATTERNS) as Array<keyof typeof PATTERNS>)) {
    const p = PATTERNS[name];
    out = out.replace(p.re, p.fn as (...a: string[]) => string);
  }
  return out;
}

export function redact(value: unknown, opts: RedactionOptions = {}): unknown {
  const keys = [...SECRET_KEYS, ...(opts.keys ?? [])].map((k) => k.toLowerCase());
  const fields = new Set(opts.fields ?? []);
  const walk = (v: unknown, path: string, depth: number): unknown => {
    if (fields.has(path)) return `[REDACTED ${hashValue(v)}]`;
    if (depth > 12) return "[TRUNCATED]";
    if (opts.metadataOnly && (v === null || typeof v !== "object")) return v === null ? null : `[${typeof v} ${hashValue(v)}]`;
    if (typeof v === "string") return redactString(v.length > 4000 ? v.slice(0, 4000) + "…[truncated]" : v, opts.patterns);
    if (Array.isArray(v)) return v.slice(0, 200).map((x, i) => walk(x, path ? `${path}.${i}` : String(i), depth + 1));
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, x] of Object.entries(v)) {
        const p = path ? `${path}.${k}` : k;
        const lk = k.toLowerCase();
        const secret = keys.some((s) => lk.includes(s)) || SECRET_KEYS_EXACT.includes(lk);
        out[k] = secret && !fields.has(p) ? "[REDACTED]" : walk(x, p, depth + 1);
      }
      return out;
    }
    return v;
  };
  return walk(value, "", 0);
}
