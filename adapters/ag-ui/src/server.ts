// SPDX-License-Identifier: Elastic-2.0

import type {PlatformRunAuthority} from "./authority.ts";
import {MAX_RUN_INPUT_BYTES} from "./admission.ts";
import {createAguiHandler, type RuntimeConfig} from "./runtime.ts";

export interface SupervisedServerConfig extends RuntimeConfig {
  readonly hostname: "127.0.0.1" | "::1";
  readonly port: number;
}

export interface SupervisedServer {
  readonly hostname: string;
  readonly port: number;
  stop(closeActiveConnections?: boolean): void;
}

interface BunServeRuntime {
  serve(options: {
    hostname: string;
    port: number;
    maxRequestBodySize: number;
    fetch: (request: Request) => Promise<Response>;
    development: false;
  }): SupervisedServer;
}

/** Bind only loopback; the supervisor supplies the unprivileged process user. */
export function startSupervisedServer(
  authority: PlatformRunAuthority,
  config: SupervisedServerConfig,
): SupervisedServer {
  if (!Number.isSafeInteger(config.port) || config.port < 1_024 || config.port > 65_535) {
    throw new RangeError("adapter port must be an unprivileged TCP port");
  }
  const handler = createAguiHandler(authority, config);
  const runtime = (globalThis as typeof globalThis & {Bun?: BunServeRuntime}).Bun;
  if (runtime === undefined) throw new Error("the supervised adapter requires the pinned Bun runtime");
  return runtime.serve({
    hostname: config.hostname,
    port: config.port,
    maxRequestBodySize: MAX_RUN_INPUT_BYTES,
    fetch: handler,
    development: false,
  });
}
