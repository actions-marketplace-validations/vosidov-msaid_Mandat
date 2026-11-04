// Tiny durable key/value collection persisted as one JSON file (atomic rewrite on change).
// Good enough for a single-node control plane; swap for a database behind the same interface later.

import { readJson, writeJsonAtomic } from "./util.ts";

export class JsonCollection<T extends { id: string }> {
  private items = new Map<string, T>();
  readonly path: string | null;

  constructor(path: string | null) {
    this.path = path;
    if (path) for (const item of readJson<T[]>(path, [])) this.items.set(item.id, item);
  }

  get(id: string): T | undefined { return this.items.get(id); }
  all(): T[] { return [...this.items.values()]; }
  filter(fn: (t: T) => boolean): T[] { return this.all().filter(fn); }

  put(item: T): T {
    this.items.set(item.id, item);
    this.flush();
    return item;
  }

  update(id: string, fn: (t: T) => T): T | undefined {
    const cur = this.items.get(id);
    if (!cur) return undefined;
    const next = fn(cur);
    this.items.set(id, next);
    this.flush();
    return next;
  }

  delete(id: string): boolean {
    const ok = this.items.delete(id);
    if (ok) this.flush();
    return ok;
  }

  private flush(): void {
    if (this.path) writeJsonAtomic(this.path, this.all());
  }
}
