// SPDX-License-Identifier: GPL-3.0-only

export class MessageDO implements DurableObject {
  constructor(private readonly ctx: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;

    if (path === "/put" && request.method === "POST") {
      const body = await request.json<{
        ciphertext: string;
        ttl: number;
        password: boolean;
      }>();
      const expiresAt = Date.now() + body.ttl * 1000;
      await this.ctx.storage.put({
        ciphertext: body.ciphertext,
        expiresAt,
        password: body.password === true,
      });
      await this.ctx.storage.setAlarm(expiresAt);
      return Response.json({ ok: true });
    }

    if (path === "/open" && request.method === "POST") {
      const record = await this.readLive();
      await this.wipe();
      if (!record) {
        return Response.json({ state: "gone" }, { status: 404 });
      }
      return Response.json({
        ciphertext: record.ciphertext,
        password: record.password,
      });
    }

    if (path === "/status" && request.method === "GET") {
      const record = await this.readLive();
      if (!record) {
        await this.wipe();
        return new Response(null, { status: 404 });
      }
      return new Response(null, { status: 204 });
    }

    return new Response(null, { status: 404 });
  }

  async alarm(): Promise<void> {
    await this.wipe();
  }

  private async readLive(): Promise<{ ciphertext: string; password: boolean } | null> {
    const data = await this.ctx.storage.get<unknown>(["ciphertext", "expiresAt", "password"]);
    const ciphertext = data.get("ciphertext");
    const expiresAt = data.get("expiresAt");
    const password = data.get("password") === true;
    if (typeof ciphertext !== "string" || typeof expiresAt !== "number") {
      return null;
    }
    if (expiresAt <= Date.now()) {
      return null;
    }
    return { ciphertext, password };
  }

  private async wipe(): Promise<void> {
    await this.ctx.storage.deleteAll();
    await this.ctx.storage.deleteAlarm();
  }
}
