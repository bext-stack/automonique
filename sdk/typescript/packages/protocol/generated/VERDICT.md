<!-- SPDX-License-Identifier: Apache-2.0 -->

# R1-11 — TypeScript codegen spike verdict

**Verdict: recommended with named constraints.**

Generation from a Rust-owned schema description preserves every property the
contract named, on a slice chosen to be hostile rather than representative. The
constraints below are real and belong in `R8B`'s plan; none of them is a reason
to abandon the one-source-of-truth rule.

## Measured

| Property | Result | How it was measured |
|---|---|---|
| Bound preservation | pass | Generated validators accept the exact UTF-8 byte limit and refuse one byte over, for two branded domains and a bounded integer at the signed 64-bit ceiling. Measured in bytes, not code units: a multibyte string that fits by `length` and not by bytes is refused. |
| Brand distinctness | pass | `brand-crossing.ts` fails with `Type 'TurnId' is not assignable to type 'SessionId'`. `bound-widening.ts` fails with `Type 'string' is not assignable to type 'TurnId'`, so a raw string cannot bypass a validator. |
| Union exhaustiveness | pass | `union-nonexhaustive.ts` fails with `not assignable to parameter of type 'never'`. `payload-free-variant.ts` fails with `Property 'text' does not exist`, so the payload-free variant did not degenerate into optional-payload. |
| Unknown-event tolerance | pass | An unseen event kind decodes to an explicit unknown representation that preserves both kind and payload, neither throwing nor dropping, and remains bounded. |
| Reproducibility | pass | Regeneration is byte-identical across repeated runs and across reordered input. No date, timestamp, host path or allocation-dependent ordering reaches the output. |

Runtime behaviour measured under **bun 1.3.13**; type-level behaviour under the
**TypeScript compiler resolved offline by `npx --offline tsc`**.

## Constraints `R8B` must plan for

1. **Integers must be `bigint`, not `number`.** The wire carries signed 64-bit
   values and a JavaScript `number` loses them above 2^53. The generated
   bounded-integer type is branded `bigint`. An SDK that exposes these as
   `number` for ergonomics reintroduces the loss.
2. **Bounds are byte bounds.** `string.length` is UTF-16 code units. Every
   generated validator measures UTF-8 bytes, which costs an encode per
   validation. A generator that used `length` would pass a naive test suite and
   silently accept over-limit multibyte values.
3. **Exhaustiveness needs the emitted helper.** `assertNever*` is what turns a
   missing variant into a compile error. If hand-written SDK code switches over
   a generated union without it, the property is lost at that call site rather
   than in the generator.
4. **No content digest is embedded.** `automonique-protocol` has no
   dependencies and therefore no hash implementation, so the generated file
   carries no schema digest. `typescript-sdk.md` requires a released SDK to
   record its exact schema digest, so `R8B` needs a hashing step *outside* this
   crate — which is also where the `R1-10` digest comparison gets its input.
5. **The zero-diff rule needs a CI step.** Reproducibility is asserted by the
   spike's own tests, but nothing yet regenerates into a temporary tree during
   CI and diffs. `R8B` should add that; the plan workflow's existing
   derived-files check is the natural place.

## Not measured

- **Whether this generalizes to the full protocol surface.** The slice contains
  every construct the contract demanded, but it is one union, two branded
  domains and two enums. Generic containers, recursive types and cross-module
  references are unmeasured and are the most likely source of surprise.
- **Client generation.** This spike generates wire types and validators only. No
  low-level client, transport binding or service description was generated, so
  the claim covers types and validators rather than the whole artifact list in
  `typescript-sdk.md` § One source of truth.

Both are recorded as `null` with a reason rather than assumed to follow.

## What a failure would have cost

Had brand distinctness or bound preservation failed, `R8B` would face a choice
between hand-writing the wire layer — which is the duplication the
one-source-of-truth rule exists to prevent — and shipping an SDK whose types
compile while admitting values the daemon refuses. The second is worse: it moves
a refusal from the client's compiler to the server's wire, where the operator
sees it instead of the developer.
