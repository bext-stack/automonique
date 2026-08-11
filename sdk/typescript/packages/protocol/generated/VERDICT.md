<!-- SPDX-License-Identifier: Apache-2.0 -->

# R1-11 — TypeScript codegen spike verdict

**Verdict: recommended with named constraints.**

Generation from a Rust-owned schema description preserves four of the five
properties the contract named, on a slice chosen to be hostile rather than
representative. The fifth, brand distinctness, is a **partial**: the brand holds
in the type checker and erases completely in the running value. The constraints
below are real and belong in `R8B`'s plan; none of them is a reason to abandon
the one-source-of-truth rule.

## Measured

| Property | Result | How it was measured |
|---|---|---|
| Bound preservation | pass | Generated validators accept the exact UTF-8 byte limit and refuse one byte over, for two branded domains and a bounded integer at the signed 64-bit ceiling. Measured in bytes, not code units: a multibyte string that fits by `length` and not by bytes is refused. |
| Brand distinctness | partial | Compile time holds: `brand-crossing.ts` fails with `Type 'TurnId' is not assignable to type 'SessionId'`, and `bound-widening.ts` fails with `Type 'string' is not assignable to type 'TurnId'`, so a raw string cannot bypass a validator. Runtime does not: the brand **erases** entirely. Every generated constructor ends in `return value as TurnId`, so under bun `TurnId("abc")` and `SessionId("abc")` are both `typeof "string"`, compare `===` equal across domains, carry no `__brand` property (it reads `undefined`) and serialize as bare strings. The contract records a brand that exists at compile time and erases at runtime as a partial pass, so this is one. `conformance/spike-runtime.ts` measures the erasure and prints `brand-runtime-existence: erased`; `tests/codegen.rs` compares that against the emitted constructors and against this row, so the three cannot drift apart. |
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
6. **The brand is compile-time only; it erases in the value.** This is the
   partial in the table above, and it is the one constraint that comes from a
   property the spike did not fully preserve. What it costs `R8B`: nothing that
   runs can ask which domain a string came from. A client that holds session and
   turn identifiers in the same `Map`, a redactor that wants to treat identifier
   text differently by domain, or a boundary that receives a value from
   untyped JavaScript — `JSON.parse`, a plain `.js` caller, an `any` from a
   third-party library — all get zero help from the brand, and a mistake there
   surfaces on the daemon's wire rather than in the developer's editor. `R8B`
   must therefore (a) re-validate at every trust boundary by calling the
   generated constructor, never by casting, since possessing the type is not
   evidence that the bound was ever checked; and (b) never build runtime
   dispatch, equality or storage keyed on the brand, because at runtime there is
   nothing there. Budget for the boundary re-validation: it is an encode plus a
   comparison per identifier, the same cost the bound check already pays.

## Why the brand is not carried into the value

The emitter could have been changed to make the brand survive; it was not, and
the reason belongs in the record rather than in someone's memory.

A brand cannot be a property on the string, because a JavaScript primitive
cannot hold one: inside a module, `value.__brand = "TurnId"` throws
`TypeError: Attempted to assign to readonly property` and the value is unchanged.
Carrying a brand therefore requires boxing every identifier — `new String(value)`
or a wrapper object — which changes the runtime representation of a wire value:

- `typeof id` becomes `"object"` and `id === "abc"` becomes `false`, so every
  equality comparison, `Map`/`Set` membership test and object key in every
  consumer silently changes meaning. That is a much larger correctness hazard
  than the one the brand removes;
- it costs one allocation per identifier on the decode path, which runs per
  event rather than per turn;
- the ergonomics the SDK exists to provide — passing an identifier to
  `fetch`, template literals, structured logging — all start needing an unwrap.

The spike's job is to decide whether generation preserves the protocol's
properties, not to design the identifier representation, so the emitter's output
shape was left alone and the partial recorded instead. `generated/spike.ts` is
under a zero-diff reproducibility test, so changing that shape is a deliberate
decision for `R8B` to make with the cost above in front of it — not a detail to
change in passing.

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

Had brand distinctness or bound preservation failed *outright*, `R8B` would face
a choice between hand-writing the wire layer — which is the duplication the
one-source-of-truth rule exists to prevent — and shipping an SDK whose types
compile while admitting values the daemon refuses. The second is worse: it moves
a refusal from the client's compiler to the server's wire, where the operator
sees it instead of the developer.

Brand distinctness did not fail outright; it half-failed, and the half that is
missing costs exactly what constraint 6 describes. The reason a partial is worth
recording as loudly as a failure is that it is the shape of result an SDK team
rounds up: "brands work" is true of every line of TypeScript anyone will read,
and false of every line of JavaScript that calls it.
