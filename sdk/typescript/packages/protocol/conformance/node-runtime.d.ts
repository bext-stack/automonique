// SPDX-License-Identifier: Apache-2.0

// Only the runtime surface the conformance runner uses. Declared locally so the
// package typechecks offline without a dependency, matching the approach in
// `@automonique/lab`'s `node-net.d.ts`.

declare module "node:fs" {
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function readFileSync(path: string): Uint8Array;
  export function writeFileSync(path: string, data: string): void;
  export function writeFileSync(path: string, data: Uint8Array): void;
}

declare const process: {
  readonly argv: readonly string[];
  readonly version: string;
  readonly release?: {readonly name?: string};
  exit(code: number): never;
};

// Present only under Bun. Read so the results artifact can name the runtime
// that actually ran, rather than the Node version Bun reports for compatibility.
declare const Bun: {readonly version: string} | undefined;
