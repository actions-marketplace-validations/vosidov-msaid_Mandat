// Single source of truth for the version: package.json (one level up from both src/ and dist/).
import { readFileSync } from "node:fs";

export const VERSION: string = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;
