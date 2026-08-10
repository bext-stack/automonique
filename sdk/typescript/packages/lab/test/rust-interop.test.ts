// SPDX-License-Identifier: Apache-2.0

import {afterEach, expect, test} from "bun:test";
import {existsSync, mkdtempSync, rmSync, statSync} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
import {
  BunUnixSocketConnector,
  FramedLabTransport,
  LabClient,
} from "../src/index.ts";

const interopRequested = Bun.env.AUTOMONIQUE_RUN_RUST_INTEROP === "1";
const executable = Bun.env.AUTOMONIQUE_LAB_BIN;
const temporaryDirectories: string[] = [];

afterEach(() => {
  while (temporaryDirectories.length > 0) {
    rmSync(temporaryDirectories.pop()!, {recursive: true, force: true});
  }
});

if (interopRequested && executable === undefined) {
  test("requires the prebuilt Rust interop binary", () => {
    throw new Error("set AUTOMONIQUE_LAB_BIN to the prebuilt automonique-lab binary");
  });
}

if (interopRequested && executable !== undefined) {
  test("Bun selects, resumes, cancels, and observes one durable Rust unit", async () => {
    const binary = resolve(executable);
    if (!existsSync(binary) || !statSync(binary).isFile()) {
      throw new Error("AUTOMONIQUE_LAB_BIN is not a file");
    }
    const root = mkdtempSync(join(tmpdir(), "automonique-rust-interop-"));
    temporaryDirectories.push(root);
    const state = join(root, "state.sqlite3");
    const buildRoot = join(root, "build");
    const base = "3637390b5298744b1404b9f4d0655671c4013752";
    const objectiveId = "rust-interop-objective";

    const serve = async <T>(request: (client: LabClient) => Promise<T>, sequence: number): Promise<T> => {
      const socket = join(root, `lab-${sequence}.sock`);
      const process = Bun.spawn([
        binary,
        "serve-once",
        "--socket", socket,
        "--state", state,
        "--build-root", buildRoot,
        "--base", base,
        "--lease-path", "sdk/typescript/packages/lab",
      ], {stdout: "ignore", stderr: "ignore"});
      for (let attempt = 0; attempt < 500 && !existsSync(socket); attempt += 1) {
        if (process.exitCode !== null) throw new Error("Rust interop server exited before binding");
        await Bun.sleep(10);
      }
      if (!existsSync(socket)) {
        process.kill();
        throw new Error("Rust interop server did not bind before the deadline");
      }
      const client = new LabClient(new FramedLabTransport(
        new BunUnixSocketConnector(socket),
        {timeoutMs: 10_000},
      ));
      try {
        const result = await request(client);
        if (await process.exited !== 0) throw new Error("Rust interop server failed");
        return result;
      } finally {
        if (process.exitCode === null) {
          process.kill();
          await process.exited;
        }
      }
    };

    const selected = await serve((client) => client.select({
      requestId: "rust-select",
      objectiveId,
      expectedBase: base,
      execution: "synthetic",
      providerPolicy: {
        kind: "synthetic",
        driver: "in_process_fixture",
        network: "deny",
        authentication: "none",
        maxModelCalls: 0,
        maxCostMicrounits: 0,
      },
      budget: {
        maxWallMs: 1_000,
        maxCpuMs: 1_000,
        maxDiskBytes: 16_384,
        maxOutputBytes: 16_384,
        maxPids: 2,
        maxModelCalls: 0,
        maxCostMicrounits: 0,
        enforcement: "synthetic_in_process",
      },
    }), 1);
    expect(selected.kind).toBe("selected");
    if (selected.kind !== "selected") throw new Error("Rust selection was denied");

    if (selected.unit.checkpointId === null) throw new Error("Rust selection lacked a checkpoint");
    const resumed = await serve((client) => client.resume({
      requestId: "rust-resume",
      objectiveId,
      unitId: selected.unit.unitId,
      checkpointId: selected.unit.checkpointId!,
      expectedRevision: selected.unit.revision,
      idempotencyKey: "rust-resume-key",
    }), 2);
    expect(resumed.kind).toBe("action");
    if (resumed.kind !== "action") throw new Error("Rust resume was denied");
    expect(resumed.receipt.status).toBe("accepted");

    const cancelled = await serve((client) => client.cancel({
      requestId: "rust-cancel",
      objectiveId,
      unitId: selected.unit.unitId,
      expectedRevision: resumed.unit.revision,
      idempotencyKey: "rust-cancel-key",
      reason: "operator_request",
    }), 3);
    expect(cancelled.kind).toBe("action");
    if (cancelled.kind !== "action") throw new Error("Rust cancellation was denied");
    expect(cancelled.receipt.status).toBe("accepted");

    const observed = await serve((client) => client.observe({
      requestId: "rust-observe",
      objectiveId,
      unitId: selected.unit.unitId,
      afterSequence: 0,
      limit: 64,
    }), 4);
    expect(observed.kind).toBe("observed");
    if (observed.kind !== "observed") throw new Error("Rust observation was denied");
    expect(observed.events.filter((event) => event.type === "unit.selected")).toHaveLength(1);
    expect(observed.events.filter((event) => event.type === "unit.resumed")).toHaveLength(1);
    expect(observed.events.filter((event) => event.type === "unit.cancelled")).toHaveLength(1);
    expect(new Set(observed.events.map((event) => event.sequence)).size).toBe(observed.events.length);
  });
}
