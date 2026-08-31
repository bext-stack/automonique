// SPDX-License-Identifier: Elastic-2.0

/**
 * Replay a live attention capture through Automonique Mobile's real reducers.
 *
 * This is an entry point, not an implementation. The source inventory, the
 * board, the succession fence and the projection all come from
 * `src/core/attention-source-{board,inventory,projection}.ts` in the mobile
 * checkout the operator names, and the wire decoding comes from the vendored
 * `@automonique/sdk` that checkout resolves. Nothing here decides what Mobile
 * shows; a second implementation that agreed with itself would prove nothing.
 *
 * It reads one `automonique.attention-live-replay-input/v1` document on stdin
 * and prints one `automonique.attention-live-projection/v1` document on
 * stdout, in the same shape the ShellDeck driver prints, so
 * `tools/run_attention_live_parity.py` compares two projections rather than
 * two vocabularies.
 *
 * Two mechanical adapters are needed and are deliberately small:
 *
 *   1. Node resolves extensionless relative imports only through a hook, and
 *      the mobile sources are authored for a bundler that does. The hook below
 *      appends the extension and changes nothing else.
 *   2. The vendored SDK ships `parseCanonical` but no standalone attention
 *      snapshot decoder — the snapshot only ever arrives inside a response
 *      envelope the transport owns. So the captured canonical bytes are parsed
 *      by the SDK's own parser and the resulting tree is mapped onto the
 *      `AttentionSourceSnapshot` interface field by field. That mapping is the
 *      one place this file touches the wire, it invents no field, and every
 *      value it carries came out of the deployment's bytes.
 *
 * Usage: node --experimental-transform-types mobile_live_replay.mjs <mobile-root>
 */

import { existsSync } from 'node:fs';
import { createRequire, registerHooks } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

const INPUT_SCHEMA = 'automonique.attention-live-replay-input/v1';
const OUTPUT_SCHEMA = 'automonique.attention-live-projection/v1';
const CLIENT = 'mobile';

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier.startsWith('.') && context.parentURL) {
      const direct = new URL(specifier, context.parentURL);
      if (direct.protocol === 'file:' && !existsSync(fileURLToPath(direct))) {
        for (const suffix of ['.ts', '.tsx', '/index.ts']) {
          const candidate = new URL(specifier + suffix, context.parentURL);
          if (existsSync(fileURLToPath(candidate))) {
            return nextResolve(specifier + suffix, context);
          }
        }
      }
    }
    return nextResolve(specifier, context);
  },
});

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

const root = process.argv[2];
if (!root) {
  fail('usage: mobile_live_replay.mjs <mobile-root>');
}

const core = pathToFileURL(`${root}/src/core/`).href;
const board = await import(`${core}attention-source-board.ts`);
const inventoryModule = await import(`${core}attention-source-inventory.ts`);
const projectionModule = await import(`${core}attention-source-projection.ts`);
// The SDK is the one the mobile checkout resolves, not one this file's own
// directory happens to see. Resolving it from the checkout's `package.json` is
// what keeps the decoders under test the vendored ones a phone build ships.
const require = createRequire(pathToFileURL(`${root}/package.json`).href);
const sdk = await import(pathToFileURL(require.resolve('@automonique/sdk')).href);

/** Unwrap the SDK's tagged canonical tree into plain JavaScript. */
function plain(value) {
  switch (value.kind) {
    case 'null':
      return null;
    case 'bool':
    case 'integer':
    case 'string':
      return value.value;
    case 'array':
      return value.items.map(plain);
    case 'object': {
      const result = {};
      for (const [name, item] of value.entries) {
        result[name] = plain(item);
      }
      return result;
    }
    default:
      throw new Error(`canonical value kind ${value.kind} is unknown`);
  }
}

function base64(value) {
  return new Uint8Array(Buffer.from(value, 'base64'));
}

/**
 * Map one canonical attention snapshot onto the interface Mobile's board
 * consumes. Every field is copied across; none is defaulted or inferred.
 */
function snapshotFrom(canonicalBase64) {
  const document = plain(sdk.parseCanonical(base64(canonicalBase64)));
  return {
    schema: document.schema,
    semantics: document.semantics,
    source: { kind: document.source.kind, id: document.source.id },
    project: document.project,
    user_workspace: document.user_workspace,
    revision: document.revision,
    previous_revision: document.previous_revision,
    observed_at_ms: document.observed_at_ms,
    items: document.items.map((item) => ({
      id: item.id,
      revision: item.revision,
      observed_at_ms: item.observed_at_ms,
      state: item.state,
      reason: item.reason,
      unread: item.unread,
      nested_agent_path: item.nested_agent_path,
      platform_session: item.platform_session,
    })),
  };
}

function sourceKey(source) {
  return `${source.kind}:${source.id}`;
}

function sameSource(left, right) {
  return left.kind === right.kind && left.id === right.id;
}

/** Decode every captured page with the SDK's own work-context decoder. */
function recordsFrom(pages) {
  const records = [];
  for (const page of pages) {
    const decoded = sdk.decodeWorkContextPage(base64(page));
    records.push(...decoded.items);
  }
  return records;
}

function project(current, sources) {
  const visible = board.visibleAttentionItems(current);
  const perSource = {};
  for (const source of sources) {
    const retained = board.retainedAttentionSnapshot(current, source);
    const status = board.attentionSourceStatus(current, source);
    perSource[sourceKey(source)] = {
      status:
        status.kind === 'refused'
          ? { kind: 'refused', category: status.category }
          : status.kind === 'unavailable'
            ? { kind: 'unavailable', reason: status.reason }
            : { kind: status.kind },
      generation: retained === null ? null : String(retained.revision),
      visible_items: visible
        .filter((entry) => sameSource(entry.source, source))
        .map((entry) => entry.item.id),
    };
  }
  return {
    sources: perSource,
    visible_items: visible.map((entry) => ({
      source: sourceKey(entry.source),
      item: entry.item.id,
      state: entry.item.state,
      reason: entry.item.reason,
    })),
    presents_attention: visible.length > 0,
  };
}

function applyRead(current, source, read) {
  if (read.kind === 'refusal') {
    return {
      board: board.markAttentionSourceRefused(current, source, read.category),
      outcome: { state: 'refused_by_server', category: read.category },
    };
  }
  if (read.kind === 'unavailable') {
    return {
      board: board.markAttentionSourceUnavailable(
        current,
        source,
        read.reason ?? 'transport',
      ),
      outcome: { state: 'unavailable', reason: read.reason ?? 'transport' },
    };
  }
  if (read.kind !== 'snapshot') {
    return {
      board: current,
      outcome: { state: 'input_invalid', detail: `read kind ${read.kind}` },
    };
  }
  let snapshot;
  try {
    snapshot = snapshotFrom(read.snapshot_canonical_base64);
  } catch (error) {
    return {
      board: current,
      outcome: { state: 'decode_refused', detail: String(error?.message ?? error) },
    };
  }
  try {
    const applied = board.applyAttentionSnapshot(current, source, snapshot, {
      mode: read.mode ?? 'continuous',
    });
    return {
      board: applied.board,
      outcome: { state: 'applied', outcome: applied.outcome },
    };
  } catch (error) {
    // The board refusing a succession is an answer, not a crash: it is exactly
    // what keeps a client from resynchronizing onto whatever the next read
    // claims. It is recorded so the comparison can see the two clients refuse
    // the same read for the same reason.
    return {
      board: current,
      outcome: { state: 'refused', error: String(error?.category ?? error?.message ?? error) },
    };
  }
}

let raw = '';
for await (const chunk of process.stdin) {
  raw += chunk;
}
let input;
try {
  input = JSON.parse(raw);
} catch (error) {
  fail(`replay input is not JSON: ${error.message}`);
}
if (input.schema !== INPUT_SCHEMA) {
  fail(`input document is not ${INPUT_SCHEMA}`);
}

const target = {
  project: input.target.project,
  userWorkspace: input.target.user_workspace,
};

let inventory;
try {
  inventory = inventoryModule.deriveAttentionSourceInventory(
    target,
    recordsFrom(input.work_context_pages_canonical_base64 ?? []),
    input.review_presence,
  );
} catch (error) {
  process.stdout.write(
    `${JSON.stringify({
      schema: OUTPUT_SCHEMA,
      client: CLIENT,
      inventory: {
        state: 'refused',
        error: String(error?.category ?? error?.message ?? error),
      },
      board: { state: 'absent' },
      sources: {},
      visible_items: [],
      presents_attention: false,
      passes: [],
    })}\n`,
  );
  process.exit(0);
}

const sources = [...inventory.sources];
let current = board.createAttentionSourceBoard(target, sources);
const passes = [];
for (const pass of input.passes ?? []) {
  const outcomes = {};
  for (const entry of pass.sources ?? []) {
    const source = { kind: entry.source.kind, id: entry.source.id };
    if (!sources.some((candidate) => sameSource(candidate, source))) {
      outcomes[sourceKey(source)] = { state: 'not_inventoried' };
      continue;
    }
    const applied = applyRead(current, source, entry.read);
    current = applied.board;
    outcomes[sourceKey(source)] = applied.outcome;
  }
  passes.push({ outcomes, projection: project(current, sources) });
}

const summary = projectionModule.summarizeAuthoritativeAttention(current);

process.stdout.write(
  `${JSON.stringify(
    {
      schema: OUTPUT_SCHEMA,
      client: CLIENT,
      inventory: { state: 'derived', sources: sources.map(sourceKey) },
      board: { state: 'constructed' },
      ...project(current, sources),
      passes,
      projection_summary: summary,
    },
    (_key, value) => (typeof value === 'bigint' ? String(value) : value),
  )}\n`,
);
