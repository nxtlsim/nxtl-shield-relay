// SPDX-License-Identifier: GPL-3.0-only

import { runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import type { MessageDO } from "../src/message";

const ALLOWED = "https://nxtlsim.github.io";
const CIPHER = "dGVzdC1jaXBoZXJ0ZXh0LW5vdC1yZWFsLWRhdGE"; // opaque base64-ish blob

function uniqueIp(suffix: string): Record<string, string> {
  // Distinct addresses so tests do not share a rate-limit bucket.
  const n = Math.abs(hash(suffix)) % 200 + 1;
  const m = Math.abs(hash(suffix + "b")) % 200 + 1;
  return { "CF-Connecting-IP": `198.51.100.${n}`, "X-Test-Id": suffix, "CF-Ray": `${m}` };
}

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}

async function create(
  ciphertext = CIPHER,
  ttl = 3600,
  extra: Record<string, string> = uniqueIp("create-" + Math.random()),
  origin = ALLOWED,
  password?: boolean,
): Promise<Response> {
  const body: Record<string, unknown> = { ciphertext, ttl };
  if (password !== undefined) body.password = password;
  return exports.default.fetch("https://relay.test/v1/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json", Origin: origin, ...extra },
    body: JSON.stringify(body),
  });
}

describe("nxtl-shield-relay", () => {
  it("creates a message and returns a 128-bit id", async () => {
    const res = await create();
    expect(res.status).toBe(201);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe(ALLOWED);
    expect(res.headers.get("Cache-Control")).toBe("no-store");
    const body = await res.json<{ id: string }>();
    expect(body.id).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("status is 204 while waiting and 404 after open", async () => {
    const created = await (await create(CIPHER, 3600, uniqueIp("status"), ALLOWED)).json<{
      id: string;
    }>();
    const headers = { Origin: ALLOWED, ...uniqueIp("status-get") };
    const waiting = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/status`, {
      headers,
    });
    expect(waiting.status).toBe(204);
    expect(await waiting.text()).toBe("");

    const first = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/open`, {
      method: "POST",
      headers,
    });
    expect(first.status).toBe(200);
    const payload = await first.json<{ ciphertext: string; password: boolean }>();
    expect(payload.ciphertext).toBe(CIPHER);
    expect(payload.password).toBe(false);

    const goneStatus = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/status`, {
      headers,
    });
    expect(goneStatus.status).toBe(404);
    expect(await goneStatus.json()).toEqual({ state: "gone" });
  });

  it("opens once and then returns gone", async () => {
    const created = await (
      await create(CIPHER, 86400, uniqueIp("open-once"), ALLOWED, true)
    ).json<{ id: string }>();
    const headers = { Origin: ALLOWED, ...uniqueIp("open-once-call") };
    const first = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/open`, {
      method: "POST",
      headers,
    });
    expect(first.status).toBe(200);
    expect(await first.json()).toEqual({ ciphertext: CIPHER, password: true });

    const second = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/open`, {
      method: "POST",
      headers,
    });
    expect(second.status).toBe(404);
    expect(await second.json()).toEqual({ state: "gone" });
  });

  it("treats an expired message as gone", async () => {
    const created = await (await create(CIPHER, 3600, uniqueIp("expiry"), ALLOWED)).json<{
      id: string;
    }>();
    const stub = env.MESSAGES.get(env.MESSAGES.idFromName(created.id));
    await runInDurableObject(stub, async (_instance: MessageDO, state: DurableObjectState) => {
      await state.storage.put("expiresAt", Date.now() - 1000);
    });

    const headers = { Origin: ALLOWED, ...uniqueIp("expiry-open") };
    const status = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/status`, {
      headers,
    });
    expect(status.status).toBe(404);

    const open = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/open`, {
      method: "POST",
      headers,
    });
    expect(open.status).toBe(404);
    expect(await open.json()).toEqual({ state: "gone" });
  });

  it("alarm wipe leaves the message gone", async () => {
    const created = await (await create(CIPHER, 604800, uniqueIp("alarm"), ALLOWED)).json<{
      id: string;
    }>();
    const stub = env.MESSAGES.get(env.MESSAGES.idFromName(created.id));
    const ran = await runDurableObjectAlarm(stub);
    expect(ran).toBe(true);
    const open = await exports.default.fetch(`https://relay.test/v1/messages/${created.id}/open`, {
      method: "POST",
      headers: { Origin: ALLOWED, ...uniqueIp("alarm-open") },
    });
    expect(open.status).toBe(404);
    expect(await open.json()).toEqual({ state: "gone" });
  });

  it("rejects a disallowed origin", async () => {
    const res = await create(CIPHER, 3600, uniqueIp("cors"), "https://evil.example");
    expect(res.status).toBe(403);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
    expect(await res.json()).toEqual({ error: "origin_not_allowed" });
  });

  it("rejects preflight from a disallowed origin", async () => {
    const res = await exports.default.fetch("https://relay.test/v1/messages", {
      method: "OPTIONS",
      headers: {
        Origin: "https://not-allowed.example",
        "Access-Control-Request-Method": "POST",
      },
    });
    expect(res.status).toBe(403);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  it("allows preflight from an allowlisted origin", async () => {
    const res = await exports.default.fetch("https://relay.test/v1/messages", {
      method: "OPTIONS",
      headers: {
        Origin: "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
      },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get("Access-Control-Allow-Origin")).toBe("http://localhost:5173");
  });

  it("rejects ciphertext over the size limit", async () => {
    const huge = "A".repeat(64 * 1024 + 1);
    const res = await create(huge, 3600, uniqueIp("size"));
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "too_large" });
  });

  it("rejects a bad ttl or missing ciphertext", async () => {
    const headers = {
      "Content-Type": "application/json",
      Origin: ALLOWED,
      ...uniqueIp("bad-ttl"),
    };
    const badTtl = await exports.default.fetch("https://relay.test/v1/messages", {
      method: "POST",
      headers,
      body: JSON.stringify({ ciphertext: CIPHER, ttl: 15 }),
    });
    expect(badTtl.status).toBe(400);

    const missing = await exports.default.fetch("https://relay.test/v1/messages", {
      method: "POST",
      headers,
      body: JSON.stringify({ ttl: 3600 }),
    });
    expect(missing.status).toBe(400);
  });

  it("rate-limits repeated creates from the same hashed address", async () => {
    // Force every call to share one address.
    const same = { "CF-Connecting-IP": "192.0.2.77" };
    let limited = 0;
    let created = 0;
    for (let i = 0; i < 21; i++) {
      const res = await create(CIPHER, 3600, same, ALLOWED);
      if (res.status === 201) created += 1;
      if (res.status === 429) limited += 1;
      await res.arrayBuffer();
    }
    expect(created).toBe(20);
    expect(limited).toBe(1);
  });
});
