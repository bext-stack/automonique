// SPDX-License-Identifier: Elastic-2.0

// Dashboard development server.
//
// The web entry embeds its dashboard assets with `include_str!`, so every UI
// change otherwise costs a Rust build and a redeploy. This server serves the
// assets straight from `assets/` on every request, reloads the open page when
// one of them changes (stylesheets are swapped in place, without a reload),
// and forwards everything else to a running web entry, so the page works on
// that deployment's real data and authentication.
//
//   AUTOMONIQUE_DEV_UPSTREAM  web entry to forward to, e.g. http://127.0.0.1:18082
//   AUTOMONIQUE_DEV_HOST      that web entry's canonical host (its `Host` check)
//   AUTOMONIQUE_DEV_PORT      local port, default 4410 (bound to loopback only)
//   AUTOMONIQUE_DEV_ASSETS_DIR  optional assets directory, default ./assets
//
// Sign in with the dashboard's own credential when the browser asks: the
// `Authorization` header and session cookie pass through unchanged.

import { watch } from "node:fs";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const upstream = process.env.AUTOMONIQUE_DEV_UPSTREAM;
const canonicalHost = process.env.AUTOMONIQUE_DEV_HOST;
const port = Number(process.env.AUTOMONIQUE_DEV_PORT || 4410);
if (!upstream || !canonicalHost) {
  console.error("Set AUTOMONIQUE_DEV_UPSTREAM and AUTOMONIQUE_DEV_HOST (see the header of dev-server.js).");
  process.exit(2);
}

// AUTOMONIQUE_DEV_ASSETS_DIR serves another copy of the assets, so design
// variants can run side by side against the same web entry.
const assetsDir = process.env.AUTOMONIQUE_DEV_ASSETS_DIR
  ? process.env.AUTOMONIQUE_DEV_ASSETS_DIR.replace(/\/?$/, "/")
  : fileURLToPath(new URL("./assets/", import.meta.url));
const qrcodePath = fileURLToPath(new URL("../../../third_party/qrcode/qrcode-core.js", import.meta.url));

const LOCAL_ASSETS = new Map([
  ["/assets/dashboard.css", ["dashboard.css", "text/css; charset=utf-8"]],
  ["/assets/dashboard.js", ["dashboard.js", "text/javascript; charset=utf-8"]],
  ["/assets/platform-cockpit-core.js", ["platform-cockpit-core.js", "text/javascript; charset=utf-8"]],
  ["/favicon.svg", ["favicon.svg", "image/svg+xml"]],
]);

// External, because the dashboard policy is `script-src 'self'`.
const RELOAD_CLIENT = `"use strict";
(() => {
  const events = new EventSource("/__dev/events");
  events.addEventListener("change", ({ data }) => {
    if (data !== "dashboard.css") return window.location.reload();
    for (const link of document.querySelectorAll('link[rel="stylesheet"]')) {
      const url = new URL(link.href);
      if (url.pathname !== "/assets/dashboard.css") continue;
      url.searchParams.set("dev", Date.now().toString());
      link.href = url.toString();
    }
  });
})();
`;

const WATCHED = new Set(["dashboard.html", ...[...LOCAL_ASSETS.values()].map(([name]) => name)]);
const clients = new Set();
const encoder = new TextEncoder();
let pending = null;
watch(assetsDir, (_event, file) => {
  if (!WATCHED.has(file)) return;
  // Editors write in several steps; announce one change per burst.
  clearTimeout(pending);
  pending = setTimeout(() => {
    console.log(`changed ${file}`);
    for (const send of clients) send(file);
  }, 60);
});

function events(request) {
  let send;
  const stream = new ReadableStream({
    start(controller) {
      send = (file) => controller.enqueue(encoder.encode(`event: change\ndata: ${file}\n\n`));
      controller.enqueue(encoder.encode(": connected\n\n"));
      clients.add(send);
      request.signal.addEventListener("abort", () => clients.delete(send));
    },
    cancel() {
      clients.delete(send);
    },
  });
  return new Response(stream, {
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-store" },
  });
}

async function forward(request) {
  const url = new URL(request.url);
  const headers = new Headers(request.headers);
  headers.set("Host", canonicalHost);
  headers.set("X-Forwarded-Proto", "https");
  headers.delete("Accept-Encoding");
  const response = await fetch(new URL(url.pathname + url.search, upstream), {
    method: request.method,
    headers,
    body: ["GET", "HEAD"].includes(request.method) ? undefined : await request.arrayBuffer(),
    redirect: "manual",
  });
  const out = new Headers(response.headers);
  // The body is already decoded, and HSTS has no business on a loopback origin.
  for (const name of ["Content-Encoding", "Content-Length", "Strict-Transport-Security"]) out.delete(name);
  return { response, headers: out };
}

const server = Bun.serve({
  hostname: "127.0.0.1",
  port,
  async fetch(request) {
    const { pathname } = new URL(request.url);
    if (pathname === "/__dev/events") return events(request);
    if (pathname === "/__dev/reload.js") {
      return new Response(RELOAD_CLIENT, { headers: { "Content-Type": "text/javascript; charset=utf-8" } });
    }
    // Local assets are only served once the web entry accepts the request for
    // its own copy, so they stay behind the same authentication.
    const local = LOCAL_ASSETS.get(pathname) || (pathname === "/assets/qrcode.js" && [null]);
    if (local) {
      const gate = await forward(request).catch(() => null);
      if (!gate) return new Response("Upstream web entry unreachable\n", { status: 502 });
      if (!gate.response.ok) return new Response(gate.response.body, { status: gate.response.status, headers: gate.headers });
    }
    if (local && local[0]) {
      return new Response(await readFile(assetsDir + local[0]), {
        headers: { "Content-Type": local[1], "Cache-Control": "no-store" },
      });
    }
    if (pathname === "/assets/qrcode.js") {
      return new Response(await readFile(qrcodePath), {
        headers: { "Content-Type": "text/javascript; charset=utf-8", "Cache-Control": "no-store" },
      });
    }
    try {
      const { response, headers } = await forward(request);
      // The document still goes through the web entry, which authenticates it
      // and mints the API session cookie; only its body is replaced.
      if (pathname === "/" && response.ok) {
        const html = (await readFile(assetsDir + "dashboard.html", "utf8"))
          .replace("</head>", '    <script src="/__dev/reload.js" defer></script>\n  </head>');
        return new Response(html, { status: response.status, headers });
      }
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    } catch (error) {
      return new Response(`Upstream web entry unreachable: ${error.message}\n`, { status: 502 });
    }
  },
});

console.log(`Dashboard dev server on http://${server.hostname}:${server.port}/ -> ${upstream}`);
