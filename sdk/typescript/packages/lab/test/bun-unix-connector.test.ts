// SPDX-License-Identifier: Apache-2.0

import {afterEach, describe, expect, test} from "bun:test";
import {mkdtempSync, rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {
  BunUnixSocketConnector,
  BunUnixSocketError,
  DEFAULT_LAB_REQUEST_TIMEOUT_MS,
  FramedLabTransport,
  LAB_PROTOCOL,
  type LabRequest,
} from "../src/index.ts";

const temporaryDirectories: string[] = [];
const request: LabRequest = {
  protocol: LAB_PROTOCOL,
  requestId: "request",
  op: "observe",
  objectiveId: "R0-19-synthetic",
  unitId: "unit-1",
  afterSequence: 0,
  limit: 10,
};

function temporarySocket(): {directory: string; socketPath: string} {
  const directory = mkdtempSync(join(tmpdir(), "automonique-lab-"));
  temporaryDirectories.push(directory);
  return {directory, socketPath: join(directory, "lab.sock")};
}

function framed(value: unknown): Uint8Array {
  const payload = new TextEncoder().encode(JSON.stringify(value));
  const bytes = new Uint8Array(payload.byteLength + 4);
  new DataView(bytes.buffer).setUint32(0, payload.byteLength, false);
  bytes.set(payload, 4);
  return bytes;
}

function frameBody(value: Uint8Array): string {
  const length = new DataView(value.buffer, value.byteOffset, value.byteLength).getUint32(0, false);
  return new TextDecoder().decode(value.slice(4, 4 + length));
}

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, {recursive: true, force: true});
  }
});

describe("BunUnixSocketConnector", () => {
  test("round-trips exactly one canonical frame over a real Unix socket", async () => {
    const {socketPath} = temporarySocket();
    const received: Uint8Array[] = [];
    const listener = Bun.listen({
      unix: socketPath,
      allowHalfOpen: true,
      socket: {
        data(socket, data) {
          received.push(data.slice());
          socket.end(framed({answer: true}));
        },
      },
    });
    try {
      const transport = new FramedLabTransport(new BunUnixSocketConnector(socketPath));
      expect(await transport.request(request)).toEqual({answer: true});
      expect(received).toHaveLength(1);
      expect(frameBody(received[0]!)).toBe('{"afterSequence":0,"limit":10,"objectiveId":"R0-19-synthetic","op":"observe","protocol":"automonique.lab-scenario/v1","requestId":"request","unitId":"unit-1"}');
    } finally {
      listener.stop(true);
    }
  });

  test("client abort closes the local socket without sending protocol cancel", async () => {
    const {socketPath} = temporarySocket();
    let acceptRequest: ((value: Uint8Array) => void) | undefined;
    const observed = new Promise<Uint8Array>((resolve) => { acceptRequest = resolve; });
    const listener = Bun.listen({
      unix: socketPath,
      allowHalfOpen: true,
      socket: {data(_socket, data) { acceptRequest?.(data.slice()); }},
    });
    try {
      const abort = new AbortController();
      const pending = new FramedLabTransport(new BunUnixSocketConnector(socketPath))
        .request(request, {signal: abort.signal});
      const bytes = await observed;
      abort.abort();
      await expect(pending).rejects.toMatchObject({name: "AbortError"});
      expect(frameBody(bytes)).toContain('"op":"observe"');
      expect(frameBody(bytes)).not.toContain('"op":"cancel"');
    } finally {
      listener.stop(true);
    }
  });

  test("fails closed when a real peer exceeds the connector read bound", async () => {
    const {socketPath} = temporarySocket();
    const listener = Bun.listen({
      unix: socketPath,
      allowHalfOpen: true,
      socket: {data(socket) { socket.end(new Uint8Array(128)); }},
    });
    try {
      const connector = new BunUnixSocketConnector(socketPath, {maxBufferedBytes: 32});
      await expect(new FramedLabTransport(connector).request(request)).rejects.toBeInstanceOf(BunUnixSocketError);
    } finally {
      listener.stop(true);
    }
  });

  test("bounds writes and rejects non-canonical or non-Unix addresses", async () => {
    const {socketPath} = temporarySocket();
    const listener = Bun.listen({unix: socketPath, allowHalfOpen: true, socket: {data() {}}});
    try {
      const connector = new BunUnixSocketConnector(socketPath, {maxWriteBytes: 16});
      await expect(new FramedLabTransport(connector).request(request)).rejects.toThrow("write bound");
    } finally {
      listener.stop(true);
    }
    for (const path of ["localhost:3000", "relative.sock", "/tmp/../lab.sock", "/tmp//lab.sock", `/tmp/${"x".repeat(101)}`]) {
      expect(() => new BunUnixSocketConnector(path)).toThrow("canonical absolute Unix socket path");
    }
  });

  test("uses a non-optional safe request deadline and redacts connection errors", async () => {
    expect(DEFAULT_LAB_REQUEST_TIMEOUT_MS).toBe(30_000);
    const {socketPath} = temporarySocket();
    let error: unknown;
    try {
      await new FramedLabTransport(new BunUnixSocketConnector(socketPath)).request(request);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(BunUnixSocketError);
    expect(String(error)).not.toContain(socketPath);
  });
});
