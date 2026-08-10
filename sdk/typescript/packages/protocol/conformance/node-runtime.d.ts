// SPDX-License-Identifier: Apache-2.0

// Only the runtime surface the conformance runner uses. Declared locally so the
// package typechecks offline without a dependency, matching the approach in
// `@automonique/lab`'s `node-net.d.ts`.

declare module "node:fs" {
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function writeFileSync(path: string, data: string): void;
}

declare const process: {
  readonly argv: readonly string[];
  readonly version: string;
  readonly release?: {readonly name?: string};
  exit(code: number): never;
};
