// SPDX-License-Identifier: Elastic-2.0

import {readFileSync} from "node:fs";
import {ProductionPlatformAuthority} from "./platform-authority.ts";
import {startSupervisedServer} from "./server.ts";

const port = boundedPort(environment("AUTOMONIQUE_AG_UI_PORT", "18083"));
const tokenFile = environment("AUTOMONIQUE_AG_UI_TOKEN_FILE");
const preferredNode = optionalEnvironment("AUTOMONIQUE_NODE_ID");
const authority = new ProductionPlatformAuthority({
  platformSocket: environment("AUTOMONIQUE_PLATFORM_SOCKET"),
  progressSocket: environment("AUTOMONIQUE_PROGRESS_SOCKET"),
  ...(preferredNode === undefined ? {} : {nodeId: preferredNode}),
});
startSupervisedServer(authority, {
  hostname: "127.0.0.1",
  port,
  authorize: (request) => constantTimeEqual(bearer(request), parseTokenFile(readFileSync(tokenFile, "utf8"))),
});

function environment(name: string, fallback?: string): string {
  const value = (globalThis as typeof globalThis & {process?: {env?: Record<string, string | undefined>}}).process?.env?.[name] ?? fallback;
  if (value === undefined || value.length === 0 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`${name} is required`);
  return value;
}
function optionalEnvironment(name: string): string | undefined {
  const value = (globalThis as typeof globalThis & {process?: {env?: Record<string, string | undefined>}}).process?.env?.[name];
  if (value === undefined || value.length === 0) return undefined;
  return environment(name);
}
function boundedPort(value: string): number { const port = Number(value); if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) throw new Error("invalid adapter port"); return port; }
function parseTokenFile(text: string): string {
  const token = parseConfigValue(text, "token");
  if (token.length < 32 || token.length > 4096 || /[\s\u0000-\u001f\u007f]/u.test(token)) throw new Error("adapter token file is invalid");
  return token;
}
function parseConfigValue(text: string, key: string): string {
  const lines = text.split("\n").filter((entry) => entry.startsWith(`${key}=`));
  const value = lines.length === 1 ? lines[0]!.slice(key.length + 1) : "";
  if (value.length === 0 || value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) throw new Error(`adapter ${key} is invalid`);
  return value;
}
function bearer(request: Request): string { const match = /^Bearer ([^\s]+)$/u.exec(request.headers.get("authorization") ?? ""); return match?.[1] ?? ""; }
function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left); const b = new TextEncoder().encode(right); let difference = a.byteLength ^ b.byteLength;
  for (let index = 0; index < Math.max(a.byteLength, b.byteLength); index += 1) difference |= (a[index % Math.max(1, a.byteLength)] ?? 0) ^ (b[index % Math.max(1, b.byteLength)] ?? 0);
  return difference === 0;
}
