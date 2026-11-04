// Adapter for the official MCP TypeScript SDK (@modelcontextprotocol/sdk), duck-typed so Mandat
// does not depend on it.
//
//   const guard = await createGuard({ ... });
//   const server = protect(new McpServer({ name: "billing", version: "1.0.0" }), guard);
//   server.registerTool("refund", { description, inputSchema }, handler);   // now guarded
//
//   // HTTP auth: app.use("/mcp", requireBearerAuth({ verifier: guard.sdkTokenVerifier({ InvalidTokenError }) }))

import { Guard, GuardDenied, type VerifiedAuth } from "../guard/guard.ts";
import { deniedResult } from "./server.ts";
import type { ToolDefinition } from "../guard/pinning.ts";

type ToolCallback = (...args: any[]) => unknown;
interface SdkExtra { authInfo?: { token?: string; extra?: Record<string, unknown> }; sessionId?: string }

/** Structural type of the SDK's McpServer. Method syntax keeps it assignable across SDK versions' generics. */
export interface McpServerLike {
  registerTool?(name: string, config: any, cb: any): unknown;
  tool?(name: string, ...rest: any[]): unknown;
}

interface PatchableServer {
  registerTool?: (name: string, config: Record<string, unknown>, cb: ToolCallback) => unknown;
  tool?: (name: string, ...rest: unknown[]) => unknown;
}

export function protect<S extends McpServerLike>(server: S, guard: Guard): S {
  const defs: ToolDefinition[] = [];
  let scheduled = false;
  const track = (def: ToolDefinition) => {
    defs.push(def);
    if (!scheduled) {
      scheduled = true;
      setImmediate(() => { scheduled = false; guard.registerTools(defs); });
    }
  };

  const wrap = (name: string, cb: ToolCallback): ToolCallback => async (...cbArgs: unknown[]) => {
    // SDK calls cb(args, extra) for tools with an input schema and cb(extra) without one.
    const extra = (cbArgs.length >= 2 ? cbArgs[1] : cbArgs[0]) as SdkExtra | undefined;
    const args = (cbArgs.length >= 2 ? cbArgs[0] : {}) as Record<string, unknown>;
    let auth = extra?.authInfo?.extra?.mandat as VerifiedAuth | undefined;
    try {
      auth ??= await guard.verify(extra?.authInfo?.token);
    } catch (e) {
      return { content: [{ type: "text", text: `Mandat: unauthenticated call (${(e as Error).message})` }], isError: true };
    }
    try {
      return await guard.execute({ auth, tool: name, args, sessionId: extra?.sessionId ?? null }, () => cb(...cbArgs));
    } catch (e) {
      if (e instanceof GuardDenied) return deniedResult(e);
      throw e;
    }
  };

  const s = server as PatchableServer;
  if (typeof s.registerTool === "function") {
    const orig = s.registerTool.bind(server);
    s.registerTool = (name, config, cb) => {
      track({ name, title: config.title as string, description: config.description as string, inputSchema: schemaFingerprint(config.inputSchema), annotations: config.annotations });
      return orig(name, config, wrap(name, cb));
    };
  }
  if (typeof s.tool === "function") {
    const orig = s.tool.bind(server);
    s.tool = (name: string, ...rest: unknown[]) => {
      const cb = rest.pop() as ToolCallback;
      const description = typeof rest[0] === "string" ? (rest[0] as string) : undefined;
      track({ name, description, inputSchema: schemaFingerprint(rest.find((r) => r && typeof r === "object")) });
      return orig(name, ...rest, wrap(name, cb));
    };
  }
  return server;
}

/** Zod shapes are not JSON; pin their keys + each field's description/type name instead. */
function schemaFingerprint(schema: unknown): unknown {
  if (!schema || typeof schema !== "object") return schema ?? null;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(schema as Record<string, any>)) {
    out[k] = v && typeof v === "object" && "_def" in v ? { type: v._def?.typeName, description: v.description ?? null } : v;
  }
  return out;
}
