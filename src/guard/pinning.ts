// Tool definition pinning (rug-pull / tool-poisoning protection, US-9).
// A lockfile stores sha256(name, description, inputSchema, annotations) per tool. Any later change to a
// description or schema is "drift" and is reported (warn) or blocked until re-approved with `mandat pin`.

import { existsSync } from "node:fs";
import { canonicalJson, readJson, sha256, writeJsonAtomic } from "../util.ts";

export interface ToolDefinition {
  name: string;
  title?: string;
  description?: string;
  inputSchema?: unknown;
  outputSchema?: unknown;
  annotations?: unknown;
}

export interface LockFile {
  version: 1;
  server?: string;
  pinned_at: string;
  tools: Record<string, { hash: string; description?: string }>;
}

export interface DriftReport {
  added: string[];
  removed: string[];
  changed: Array<{ name: string; before: string; after: string; description_before?: string; description_after?: string }>;
  clean: boolean;
}

export function toolHash(t: ToolDefinition): string {
  return "sha256:" + sha256(canonicalJson({
    name: t.name, title: t.title ?? null, description: t.description ?? null,
    inputSchema: t.inputSchema ?? null, outputSchema: t.outputSchema ?? null, annotations: t.annotations ?? null,
  }));
}

export function buildLock(tools: ToolDefinition[], server?: string): LockFile {
  const out: LockFile = { version: 1, server, pinned_at: new Date().toISOString(), tools: {} };
  for (const t of [...tools].sort((a, b) => a.name.localeCompare(b.name))) {
    out.tools[t.name] = { hash: toolHash(t), description: t.description?.slice(0, 200) };
  }
  return out;
}

export function diffLock(lock: LockFile, tools: ToolDefinition[]): DriftReport {
  const now = new Map(tools.map((t) => [t.name, t]));
  const added = [...now.keys()].filter((n) => !lock.tools[n]);
  const removed = Object.keys(lock.tools).filter((n) => !now.has(n));
  const changed: DriftReport["changed"] = [];
  for (const [name, t] of now) {
    const pinned = lock.tools[name];
    if (!pinned) continue;
    const h = toolHash(t);
    if (h !== pinned.hash) changed.push({ name, before: pinned.hash, after: h, description_before: pinned.description, description_after: t.description?.slice(0, 200) });
  }
  return { added, removed, changed, clean: !added.length && !removed.length && !changed.length };
}

export interface PinCheckResult { drift: DriftReport; created: boolean; blocked: Set<string> }

/**
 * Compares tools against `lockPath`. Creates the lockfile on first use (trust-on-first-use) unless `frozen`.
 * In "block" mode, changed and newly added tools are returned in `blocked`.
 */
export function checkPins(lockPath: string, tools: ToolDefinition[], opts: { mode: "warn" | "block"; frozen?: boolean; server?: string }): PinCheckResult {
  if (!existsSync(lockPath)) {
    if (opts.frozen) {
      return { drift: { added: tools.map((t) => t.name), removed: [], changed: [], clean: false }, created: false, blocked: new Set(opts.mode === "block" ? tools.map((t) => t.name) : []) };
    }
    writeJsonAtomic(lockPath, buildLock(tools, opts.server));
    return { drift: { added: [], removed: [], changed: [], clean: true }, created: true, blocked: new Set() };
  }
  const drift = diffLock(readJson<LockFile>(lockPath), tools);
  const blocked = new Set(opts.mode === "block" ? [...drift.changed.map((c) => c.name), ...drift.added] : []);
  return { drift, created: false, blocked };
}
