// Minimal argv parser: positionals, --flag, --key value, --key=value, -n 5.

export interface Args {
  _: string[];
  flags: Record<string, string | boolean>;
  str(name: string, fallback?: string): string | undefined;
  bool(name: string): boolean;
  num(name: string, fallback: number): number;
  list(name: string): string[];
}

export function parseArgs(argv: string[], booleans: string[] = []): Args {
  const _: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") { _.push(...argv.slice(i + 1)); break; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const key = eq > 0 ? a.slice(2, eq) : a.slice(2);
      if (eq > 0) flags[key] = a.slice(eq + 1);
      else if (booleans.includes(key) || argv[i + 1] === undefined || argv[i + 1]!.startsWith("-")) flags[key] = true;
      else flags[key] = argv[++i]!;
    } else if (a.startsWith("-") && a.length === 2) {
      const key = a.slice(1);
      if (booleans.includes(key) || argv[i + 1] === undefined || argv[i + 1]!.startsWith("-")) flags[key] = true;
      else flags[key] = argv[++i]!;
    } else _.push(a);
  }
  return {
    _,
    flags,
    str: (n, f) => (typeof flags[n] === "string" ? (flags[n] as string) : f),
    bool: (n) => flags[n] === true || flags[n] === "true",
    num: (n, f) => (typeof flags[n] === "string" && !Number.isNaN(Number(flags[n])) ? Number(flags[n]) : f),
    list: (n) => (typeof flags[n] === "string" ? (flags[n] as string).split(",").map((s) => s.trim()).filter(Boolean) : []),
  };
}
