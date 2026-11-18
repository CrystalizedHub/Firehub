/**
 * FireHub /load protection: Cloudflare Worker
 *
 * Route:  firehub.lol/load   (Workers > your worker > Triggers > Routes)
 *
 * Secrets (wrangler secret put NAME, or Dashboard > Settings > Variables > Encrypt):
 *   UPSTREAM_URL   the real Junkie loader URL (never shown publicly)
 *   SIGN_KEY       any long random string (used to sign request tokens)
 *
 * Optional bindings:
 *   RL             Workers Rate Limiting binding (see wrangler.toml at the bottom)
 *
 * Behaviour: anything that doesn't look like an executor gets a plain 404,
 * identical to a non-existent page, so there is nothing to probe.
 */

const BLOCKED_UA = [
  "curl", "wget", "python", "requests", "httpx", "aiohttp", "axios", "node-fetch",
  "go-http", "okhttp", "postman", "insomnia", "java/", "libwww", "scrapy",
  "httpie", "powershell", "bot", "spider", "crawler", "headless", "phantom",
  "selenium", "puppeteer", "playwright", "burp", "fiddler", "mitm",
];

const notFound = () =>
  new Response("Not Found", {
    status: 404,
    headers: {
      "content-type": "text/plain;charset=UTF-8",
      "cache-control": "no-store",
    },
  });

function looksLikeBrowserOrTool(request) {
  const h = request.headers;

  // Real browsers ALWAYS send Sec-Fetch-*; Roblox executors do not.
  if (h.has("sec-fetch-mode") || h.has("sec-fetch-dest") || h.has("sec-fetch-site")) return true;
  if (h.has("sec-ch-ua") || h.has("upgrade-insecure-requests")) return true;

  // Browser navigation / XHR signals
  const accept = (h.get("accept") || "").toLowerCase();
  if (accept.includes("text/html")) return true;
  if (h.has("origin") || h.has("referer") || h.has("cookie")) return true;

  // Common scraping tools
  const ua = (h.get("user-agent") || "").toLowerCase();
  if (!ua) return true; // executors always send something
  for (const bad of BLOCKED_UA) if (ua.includes(bad)) return true;

  // Requests that came through a proxy chain
  if (h.has("via") || h.has("x-forwarded-for")) return true;

  return false;
}

async function hmacHex(key, msg) {
  const k = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Exact path + method only. No query strings, no trailing junk.
    if (url.pathname !== "/load" || url.search !== "") return notFound();
    if (request.method !== "GET") return notFound();

    // 2. Browser / tool filter -> indistinguishable 404
    if (looksLikeBrowserOrTool(request)) return notFound();

    // 3. Rate limit per IP (needs the RL binding; skipped if not configured)
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    if (env.RL) {
      const { success } = await env.RL.limit({ key: ip });
      if (!success) return notFound();
    }

    // 4. Fetch the real loader from the hidden upstream, signed so the
    //    upstream can verify the request really came through this Worker.
    if (!env.UPSTREAM_URL || !env.SIGN_KEY) return notFound();
    const ts = Date.now().toString();
    const nonce = crypto.randomUUID();
    const sig = await hmacHex(env.SIGN_KEY, `${ts}.${nonce}`);

    let upstream;
    try {
      upstream = await fetch(env.UPSTREAM_URL, {
        headers: {
          "user-agent": "FireHub-Edge/1",
          "x-fh-ts": ts,
          "x-fh-nonce": nonce,
          "x-fh-sig": sig,
        },
        cf: { cacheTtl: 0, cacheEverything: false },
      });
    } catch {
      return notFound();
    }
    if (!upstream.ok) return notFound();

    // 5. Return it with locked-down headers: no cache, no sniffing, no indexing.
    return new Response(upstream.body, {
      status: 200,
      headers: {
        "content-type": "text/plain;charset=UTF-8",
        "cache-control": "no-store, no-cache, max-age=0",
        "x-content-type-options": "nosniff",
        "x-robots-tag": "noindex, nofollow, noarchive",
        "content-disposition": "inline",
      },
    });
  },
};

/*
# wrangler.toml
name = "firehub-load"
main = "load-worker.js"
compatibility_date = "2026-01-01"
routes = [{ pattern = "firehub.lol/load", zone_name = "firehub.lol" }]

[[unsafe.bindings]]
name = "RL"
type = "ratelimit"
namespace_id = "1001"
simple = { limit = 10, period = 60 }   # 10 requests / 60s per IP
*/
