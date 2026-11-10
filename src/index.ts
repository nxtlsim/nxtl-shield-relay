// SPDX-License-Identifier: GPL-3.0-only

export { MessageDO } from "./message";
export { RateLimitDO } from "./rate-limit";

import { allowedOrigin } from "./cors";
import { isMessageId, newMessageId } from "./id";

const ALLOWED_TTL = new Set([3600, 86400, 604800]);
const MAX_CIPHERTEXT_CHARS = 64 * 1024;
const MAX_BODY_CHARS = 70 * 1024;
const CREATE_LIMIT = 20;
const OPEN_LIMIT = 60;
const HOUR_MS = 60 * 60 * 1000;

const SECURITY_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'",
  "Permissions-Policy": "interest-cohort=()",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get("Origin");
    const corsOrigin = allowedOrigin(origin);

    if (request.method === "OPTIONS") {
      if (origin && !corsOrigin) {
        return respond(403, { error: "origin_not_allowed" }, null);
      }
      return new Response(null, {
        status: 204,
        headers: headers(corsOrigin, {
          "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Max-Age": "86400",
        }),
      });
    }

    if (origin && !corsOrigin) {
      return respond(403, { error: "origin_not_allowed" }, null);
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    if (path === "/" && (request.method === "GET" || request.method === "HEAD")) {
      return respond(
        200,
        { service: "nxtl-shield-relay" },
        corsOrigin,
        request.method === "HEAD",
      );
    }

    const create = path === "/v1/messages" && request.method === "POST";
    const open = match(path, /^\/v1\/messages\/([^/]+)\/open$/, request.method, "POST");
    const status = match(
      path,
      /^\/v1\/messages\/([^/]+)\/status$/,
      request.method,
      "GET",
      "HEAD",
    );

    if (!create && !open && !status) {
      return respond(404, { error: "not_found" }, corsOrigin);
    }

    if (create || open) {
      const limited = await rateLimit(env, request, create ? "create" : "open");
      if (limited) return respond(429, { error: "rate_limited" }, corsOrigin, false, {
        "Retry-After": "3600",
      });
    }

    if (create) {
      return createMessage(request, env, corsOrigin);
    }

    const id = (open ?? status) as string;
    if (!isMessageId(id)) {
      return respond(404, { state: "gone" }, corsOrigin, request.method === "HEAD");
    }

    const stub = env.MESSAGES.get(env.MESSAGES.idFromName(id));
    if (open) {
      const res = await stub.fetch("https://do/open", { method: "POST" });
      const body = await res.json<Record<string, unknown>>();
      return respond(res.status, body, corsOrigin);
    }

    const res = await stub.fetch("https://do/status", { method: "GET" });
    if (res.status === 204) {
      return new Response(null, { status: 204, headers: headers(corsOrigin) });
    }
    return respond(404, { state: "gone" }, corsOrigin, request.method === "HEAD");
  },
};

async function createMessage(
  request: Request,
  env: Env,
  corsOrigin: string | null,
): Promise<Response> {
  const raw = await request.text();
  if (raw.length > MAX_BODY_CHARS) {
    return respond(413, { error: "too_large" }, corsOrigin);
  }

  let parsed: unknown;
  try {
    parsed = raw ? JSON.parse(raw) : null;
  } catch {
    return respond(400, { error: "bad_request" }, corsOrigin);
  }

  if (!parsed || typeof parsed !== "object") {
    return respond(400, { error: "bad_request" }, corsOrigin);
  }

  const body = parsed as Record<string, unknown>;
  const ciphertext = body.ciphertext;
  const ttl = body.ttl;
  const password = body.password === true;

  if (typeof ciphertext !== "string" || !isCiphertext(ciphertext)) {
    return respond(400, { error: "bad_request" }, corsOrigin);
  }
  if (ciphertext.length > MAX_CIPHERTEXT_CHARS) {
    return respond(413, { error: "too_large" }, corsOrigin);
  }
  if (typeof ttl !== "number" || !ALLOWED_TTL.has(ttl)) {
    return respond(400, { error: "bad_request" }, corsOrigin);
  }

  const id = newMessageId();
  const stub = env.MESSAGES.get(env.MESSAGES.idFromName(id));
  const put = await stub.fetch("https://do/put", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ciphertext, ttl, password }),
  });
  if (!put.ok) {
    return respond(503, { error: "unavailable" }, corsOrigin);
  }
  return respond(201, { id }, corsOrigin);
}

async function rateLimit(env: Env, request: Request, action: "create" | "open"): Promise<boolean> {
  const ip = request.headers.get("CF-Connecting-IP") ?? request.headers.get("X-Forwarded-For") ?? "0";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`rl:v1:${ip}`));
  const hash = bytesToHex(new Uint8Array(digest));
  const stub = env.RATE_LIMIT.get(env.RATE_LIMIT.idFromName(hash));
  const res = await stub.fetch("https://do/hit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      action,
      limit: action === "create" ? CREATE_LIMIT : OPEN_LIMIT,
      windowMs: HOUR_MS,
    }),
  });
  if (!res.ok) return false;
  const body = await res.json<{ allowed: boolean }>();
  return !body.allowed;
}

function isCiphertext(value: string): boolean {
  if (value.length < 1) return false;
  return /^[A-Za-z0-9+/=_-]+$/.test(value);
}

function match(
  path: string,
  re: RegExp,
  method: string,
  ...allowed: string[]
): string | null {
  if (!allowed.includes(method)) return null;
  const m = path.match(re);
  return m ? m[1] : null;
}

function respond(
  status: number,
  body: Record<string, unknown>,
  corsOrigin: string | null,
  head = false,
  extra?: Record<string, string>,
): Response {
  return new Response(head ? null : JSON.stringify(body), {
    status,
    headers: headers(corsOrigin, { "Content-Type": "application/json", ...extra }),
  });
}

function headers(corsOrigin: string | null, extra: Record<string, string> = {}): Headers {
  const h = new Headers({ ...SECURITY_HEADERS, ...extra });
  if (corsOrigin) {
    h.set("Access-Control-Allow-Origin", corsOrigin);
    h.set("Vary", "Origin");
  }
  return h;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}
