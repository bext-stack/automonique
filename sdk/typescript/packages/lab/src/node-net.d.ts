// SPDX-License-Identifier: Apache-2.0

declare module "node:net" {
  export interface Socket {
    on(event: "data", listener: (data: Uint8Array) => void): this;
    on(event: "end" | "close", listener: () => void): this;
    on(event: "error", listener: (error: Error) => void): this;
    once(event: "connect", listener: () => void): this;
    once(event: "error", listener: (error: Error) => void): this;
    removeListener(event: "connect", listener: () => void): this;
    removeListener(event: "error", listener: (error: Error) => void): this;
    write(data: Uint8Array, callback: (error?: Error | null) => void): boolean;
    destroy(): this;
  }

  export function createConnection(options: {readonly path: string; readonly allowHalfOpen: true}): Socket;
}
