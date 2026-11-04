// Compiles src/ to dist/ (plain ESM JavaScript + .d.ts) and copies the console's static assets.
import { cpSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { basename, dirname, join } from "node:path";

// Resolved through package.json: TypeScript 7 no longer exports its bin/ files as subpaths.
const require = createRequire(import.meta.url);
const pkgJson = require.resolve("typescript/package.json");
const tsc = join(dirname(pkgJson), require(pkgJson).bin.tsc);
rmSync("dist", { recursive: true, force: true });
execFileSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], { stdio: "inherit" });
// Skip dot-entries: local tools may leave state folders next to the assets.
const assets = { recursive: true, filter: (src: string) => !basename(src).startsWith(".") };
cpSync("src/controlplane/console", "dist/controlplane/console", assets);
cpSync("src/scan/web", "dist/scan/web", assets);
console.log("Built dist/");
