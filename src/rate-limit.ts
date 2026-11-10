// SPDX-License-Identifier: GPL-3.0-only

export class RateLimitDO implements DurableObject {
  constructor(private readonly ctx: DurableObjectState) {}

  async fetch(request: Request): Promise<Response> {
    if (request.method !== "POST") {
      return new Response(null, { status: 404 });
    }

    const body = await request.json<{
      action: string;
      limit: number;
      windowMs: number;
    }>();

    const windowMs = Number(body.windowMs);
    const limit = Number(body.limit);
    if (!body.action || !Number.isFinite(windowMs) || !Number.isFinite(limit) || limit < 1) {
      return Response.json({ allowed: false }, { status: 400 });
    }

    const bucket = Math.floor(Date.now() / windowMs);
    const key = `${body.action}:${bucket}`;
    const count = (await this.ctx.storage.get<number>(key)) ?? 0;
    if (count >= limit) {
      return Response.json({ allowed: false, remaining: 0 });
    }

    await this.ctx.storage.put(key, count + 1);
    await this.dropOld(body.action, bucket);
    return Response.json({ allowed: true, remaining: limit - count - 1 });
  }

  private async dropOld(action: string, bucket: number): Promise<void> {
    const prefix = `${action}:`;
    const keys = await this.ctx.storage.list<number>({ prefix });
    const stale: string[] = [];
    for (const k of keys.keys()) {
      const n = Number(k.slice(prefix.length));
      if (Number.isFinite(n) && n < bucket) stale.push(k);
    }
    if (stale.length) await this.ctx.storage.delete(stale);
  }
}
