// Compiles src/ to dist/ (plain ESM JavaScript + .d.ts) and copies the console's static assets.
import { cpSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const tsc = createRequire(import.meta.url).resolve("typescript/bin/tsc");
rmSync("dist", { recursive: true, force: true });
execFileSync(process.execPath, [tsc, "-p", "tsconfig.build.json"], { stdio: "inherit" });
cpSync("src/controlplane/console", "dist/controlplane/console", { recursive: true });
cpSync("src/scan/web", "dist/scan/web", { recursive: true });
cpSync("src/scan/web", "dist/scan/web", { recursive: true });
console.log("Built dist/");
