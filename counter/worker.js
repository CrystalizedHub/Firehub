// FireHub live users counter (Cloudflare Worker + Durable Object)
// Counts unique IPs that currently have the site open.
// Hardened: only your own site's origins can connect, max 5 sockets per IP,
// tiny messages only. The page only ever shows a whole number.

const ALLOWED_ORIGINS = ["https://firehub.lol", "https://www.firehub.lol"];
const MAX_SOCKETS_PER_IP = 5;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== "/ws") return new Response("FireHub counter ok");
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected websocket", { status: 426 });
    }
    if (!ALLOWED_ORIGINS.includes(request.headers.get("Origin"))) {
      return new Response("Forbidden", { status: 403 });
    }
    const stub = env.COUNTER.get(env.COUNTER.idFromName("global"));
    return stub.fetch(request);
  },
};

export class Counter {
  constructor(state) {
    this.state = state;
  }

  open() {
    return this.state.getWebSockets().filter((ws) => ws.readyState === 1);
  }

  async fetch(request) {
    const ip = request.headers.get("CF-Connecting-IP") || "";
    const mine = this.open().filter((ws) => {
      const a = ws.deserializeAttachment();
      return a && a.ip === ip;
    });
    if (mine.length >= MAX_SOCKETS_PER_IP) {
      return new Response("Too many connections", { status: 429 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server);
    server.serializeAttachment({ ip });
    this.broadcast();
    return new Response(null, { status: 101, webSocket: client });
  }

  count() {
    const ips = new Set();
    for (const ws of this.open()) {
      const a = ws.deserializeAttachment();
      ips.add(a && a.ip ? a.ip : Math.random().toString(36));
    }
    return ips.size;
  }

  broadcast() {
    const msg = JSON.stringify({ n: this.count() });
    for (const ws of this.open()) {
      try { ws.send(msg); } catch (e) {}
    }
  }

  webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > 16) {
      try { ws.close(1009, "too big"); } catch (e) {}
      return;
    }
    if (message === "ping") { try { ws.send("pong"); } catch (e) {} }
  }

  webSocketClose(ws, code) {
    try { ws.close(code, "bye"); } catch (e) {}
    this.broadcast();
  }

  webSocketError() {
    this.broadcast();
  }
}
