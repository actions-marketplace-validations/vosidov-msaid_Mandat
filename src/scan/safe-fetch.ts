// SSRF-safe fetch for scanning URLs chosen by strangers (the public scanner page).
//
// Every address a hostname resolves to is checked at connection time (DNS lookup hook), so a public
// name that later resolves to 127.0.0.1 or 169.254.169.254 (DNS rebinding) is refused too. IP literals
// are checked before connecting. Redirects are never followed, bodies are capped, and only http(s) is allowed.

import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP, BlockList } from "node:net";

export class BlockedAddressError extends Error {}

const blocked = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of [
  ["::", 128], ["::1", 128], ["64:ff9b::", 96], ["100::", 64], ["2001::", 32], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
] as const) blocked.addSubnet(net, prefix, "ipv6");

/** True for loopback, private, link-local, CGNAT, documentation, multicast and other non-public addresses. */
export function isBlockedAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return blocked.check(address, "ipv4");
  if (family === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
    if (mapped) return blocked.check(mapped[1]!, "ipv4");
    return blocked.check(address, "ipv6");
  }
  return true;
}

export interface SafeFetchOptions {
  /** Allow private and loopback targets (self-hosted use on a trusted network). */
  allowPrivate?: boolean;
  maxBodyBytes?: number;
  /** Replaceable for tests. */
  resolve?: typeof dnsLookup;
}

export function createSafeFetch(opts: SafeFetchOptions = {}): typeof fetch {
  const maxBody = opts.maxBodyBytes ?? 1_000_000;
  const resolve = opts.resolve ?? dnsLookup;

  const lookup = (hostname: string, options: { all?: boolean; family?: number } | number, cb: (...a: any[]) => void) => {
    const all = typeof options === "object" && options.all;
    resolve(hostname, { all: true }, (err, addresses) => {
      if (err) return cb(err);
      const list = addresses as unknown as LookupAddress[];
      if (!opts.allowPrivate && list.some((a) => isBlockedAddress(a.address))) {
        return cb(new BlockedAddressError(`${hostname} resolves to a private or reserved address`));
      }
      if (all) return cb(null, list);
      cb(null, list[0]!.address, list[0]!.family);
    });
  };

  return (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(typeof input === "string" || input instanceof URL ? input.toString() : input.url);
    if (url.protocol !== "http:" && url.protocol !== "https:") throw new BlockedAddressError(`Scheme ${url.protocol} is not allowed`);
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (isIP(host) && !opts.allowPrivate && isBlockedAddress(host)) throw new BlockedAddressError(`${host} is a private or reserved address`);
    const headers = new Headers(init.headers);
    const body = typeof init.body === "string" ? init.body : init.body == null ? undefined : String(init.body);
    if (body !== undefined) headers.set("content-length", String(Buffer.byteLength(body)));

    return await new Promise<Response>((resolveRes, reject) => {
      const req = (url.protocol === "https:" ? httpsRequest : httpRequest)(url, {
        method: init.method ?? "GET",
        headers: Object.fromEntries(headers),
        lookup: lookup as never,
        timeout: 10_000,
      }, (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > maxBody) { req.destroy(new Error("Response body too large")); return; }
          chunks.push(c);
        });
        res.on("end", () => {
          // A throw here would be uncaught and kill the process: a hostile server chooses the status and headers.
          try {
            const status = res.statusCode ?? 502;
            const h = new Headers();
            for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) h.set(k, Array.isArray(v) ? v.join(", ") : v);
            const noBody = status === 204 || status === 304 || (status >= 100 && status < 200);
            resolveRes(new Response(noBody ? null : Buffer.concat(chunks), { status: status < 200 ? 200 : status, headers: h }));
          } catch (e) {
            reject(e);
          }
        });
        res.on("error", reject);
      });
      req.on("timeout", () => req.destroy(new Error("Request timed out")));
      req.on("error", reject);
      init.signal?.addEventListener("abort", () => req.destroy(new Error("Aborted")));
      if (body !== undefined) req.write(body);
      req.end();
    });
  }) as typeof fetch;
}
