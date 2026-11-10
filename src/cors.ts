// SPDX-License-Identifier: GPL-3.0-only

const EXACT = new Set([
  "https://nxtlsim.github.io",
  "https://nxtl-esim-nxtl-shield.static.hf.space",
  "https://huggingface.co",
  "chrome-extension://aihdikogmaekjmanjhdmeanhhfhiblmm",
]);

const LOCAL = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
const FIREFOX_EXTENSION =
  /^moz-extension:\/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function allowedOrigin(origin: string | null): string | null {
  if (!origin) return null;
  if (EXACT.has(origin) || LOCAL.test(origin) || FIREFOX_EXTENSION.test(origin)) return origin;
  return null;
}

export function isAllowedOrigin(origin: string | null): boolean {
  return allowedOrigin(origin) !== null;
}

export function corsHeaders(origin: string | null): Record<string, string> {
  const allowed = allowedOrigin(origin);
  if (!allowed) return {};
  return {
    "Access-Control-Allow-Origin": allowed,
    Vary: "Origin",
  };
}
