// SPDX-License-Identifier: GPL-3.0-only

const ID_RE = /^[A-Za-z0-9_-]{22}$/;

export function newMessageId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

export function isMessageId(value: string): boolean {
  return ID_RE.test(value);
}

function base64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
