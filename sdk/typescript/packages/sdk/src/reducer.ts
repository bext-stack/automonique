// SPDX-License-Identifier: Apache-2.0

import type {
  ActionReceipt,
  PlatformCursor,
  ResourceCoordinate,
  ResourceRecord,
  Snapshot,
  Subscription,
} from "../../protocol/src/index.ts";

export interface PlatformViewState {
  readonly resources: ReadonlyMap<string, ResourceRecord>;
  readonly cursors: ReadonlyMap<string, PlatformCursor>;
  readonly receipts: ReadonlyMap<string, ActionReceipt>;
  readonly resyncRequired: ReadonlySet<string>;
}

export function emptyPlatformView(): PlatformViewState {
  return {
    resources: new Map(),
    cursors: new Map(),
    receipts: new Map(),
    resyncRequired: new Set(),
  };
}

export function resourceKey(value: ResourceCoordinate): string {
  return `${value.authority}\u0000${value.kind}\u0000${value.id}`;
}

export function cursorKey(value: PlatformCursor): string {
  return `${value.authority}\u0000${value.topic}`;
}

export function reduceSnapshot(state: PlatformViewState, snapshot: Snapshot): PlatformViewState {
  const resources = new Map(state.resources);
  for (const resource of snapshot.resources) resources.set(resourceKey(resource.resource), resource);
  const cursors = new Map(state.cursors);
  const key = cursorKey(snapshot.cursor);
  cursors.set(key, snapshot.cursor);
  const resyncRequired = new Set(state.resyncRequired);
  resyncRequired.delete(key);
  return {...state, resources, cursors, resyncRequired};
}

function sameRecord(left: ResourceRecord, right: ResourceRecord): boolean {
  return resourceKey(left.resource) === resourceKey(right.resource)
    && left.freshness.revision === right.freshness.revision
    && left.freshness.state === right.freshness.state
    && left.freshness.observed_at === right.freshness.observed_at
    && left.summary === right.summary;
}

export function reduceSubscription(state: PlatformViewState, page: Subscription): PlatformViewState {
  const key = cursorKey(page.cursor);
  const prior = state.cursors.get(key);
  if (prior === undefined) return requireResync(state, key);
  let sequence = prior.sequence;
  const resources = new Map(state.resources);

  for (const event of page.events) {
    if (cursorKey(event.cursor) !== key) return requireResync(state, key);
    if (event.cursor.sequence <= sequence) {
      const existing = resources.get(resourceKey(event.resource.resource));
      if (existing !== undefined && sameRecord(existing, event.resource)) continue;
      return requireResync(state, key);
    }
    if (event.cursor.sequence !== sequence + 1n) return requireResync(state, key);
    const existing = resources.get(resourceKey(event.resource.resource));
    if (existing !== undefined && event.resource.freshness.revision < existing.freshness.revision) {
      return requireResync(state, key);
    }
    resources.set(resourceKey(event.resource.resource), event.resource);
    sequence = event.cursor.sequence;
  }

  if (page.cursor.sequence !== sequence) return requireResync(state, key);
  const cursors = new Map(state.cursors);
  cursors.set(key, page.cursor);
  const resyncRequired = new Set(state.resyncRequired);
  resyncRequired.delete(key);
  return {...state, resources, cursors, resyncRequired};
}

export function reduceReceipt(state: PlatformViewState, receipt: ActionReceipt): PlatformViewState {
  const receipts = new Map(state.receipts);
  const prior = receipts.get(receipt.id);
  if (prior !== undefined && receipt.revision < prior.revision) return state;
  receipts.set(receipt.id, receipt);
  return {...state, receipts};
}

function requireResync(state: PlatformViewState, key: string): PlatformViewState {
  const resyncRequired = new Set(state.resyncRequired);
  resyncRequired.add(key);
  return {...state, resyncRequired};
}
