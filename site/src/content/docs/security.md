---
title: Security Considerations
description: How AccessControl hardens the authorization path, what it guarantees, and the choices left to you — prototype-pollution, ReDoS, fail-closed checks, error redaction, charset/homographs, trust model and supply chain.
---

AccessControl sits on the authorization path of production systems, so v3 is
hardened against the classes of bug that matter for an access‑control library —
and documents the few decisions that remain **yours**.

:::note[The short version]
Defaults are **secure**: ASCII names, prototype‑pollution gadgets rejected,
redacted error messages, regex matching **off**. The two things to internalize:
use [`tryCan()`](#fail-closed-checks) on the request path, and treat a thrown
error as **deny**, never as allow.
:::

## Fail-closed Checks

A denial returns `granted: false`. An **error** (invalid query, a `strict`
violation, a misused async condition) is *thrown*. The danger is a caller that
wraps a check in `try/catch` and lets the catch fall through to "allow".

:::danger[Never fail open]
```js
// ❌ a thrown error here becomes an *allow* — a vulnerability
try {
  if (ac.can(role).readAny('post').granted) show();
} catch {
  show(); // WRONG
}
```
:::

Use **`tryCan()`** on the hot path: it never throws — every failure resolves to
`granted: false` (the `error` event still fires for observability). Keep
`can()` for boot/config and tests, where you *want* a typo to blow up.

```js
// ✅ fail-closed: an unknown role, bad input, or async-required all deny
if (ac.tryCan(role).readAny('post').granted) {
  show();
} else {
  deny();
}
```

See [Best Practices › can vs tryCan](/accesscontrol/best-practices/#can-vs-trycan).

## Prototype-pollution & Inherited Keys

Names (roles, resources, actions, groups, categories) are user/data‑controlled
strings used as object keys — the classic prototype‑pollution surface.

:::tip[What the library guarantees]
- The gadget names `__proto__`, `prototype` and `constructor` are **rejected**
  at validation for every name (and inside `group/member` segments) with
  `err.code === 'RESERVED_NAME'`.
- A name that collides with an inherited member (`toString`, `valueOf`,
  `hasOwnProperty`, …) is treated as **plain data** everywhere — every internal
  map read/write uses `Object.hasOwn`, so such a name never reads a function off
  a prototype or mutates a shared builtin. It simply isn't granted (or returns
  `granted: false`) instead of throwing.
- A grants object imported from JSON/DB with a `__proto__` key is rejected, not
  merged.
:::

```js
ac.can('user').readAny('toString').granted; // false (never throws)
ac.grant('__proto__');                       // throws RESERVED_NAME
```

## Conditions from Untrusted Sources

If your grants/conditions are authored **in code** (the common case), they are
trusted input. If they come from a store that **lower‑privileged users can
edit**, treat conditions as untrusted and note the following.

### Regular Expressions (ReDoS) — Opt-in

The `matches` operator compiles a regular expression. A malicious pattern can
cause catastrophic backtracking (CPU DoS).

:::caution[`matches` is disabled by default]
Enable it only for trusted condition sources:

```js
new AccessControl(grants, { engine: { allowRegex: true } });
```

When enabled, every pattern is screened for the well‑known catastrophic shapes
(`(a+)+`, `(.*)*`, …) and an absurd length, throwing `err.code ===
'UNSAFE_REGEX'`. This screen is a **heuristic, not a linear‑time guarantee** —
only a RE2‑style engine gives that. For fully untrusted authors, prefer custom
[condition functions](/accesscontrol/concepts/async/) over `matches`.
:::

### Condition Depth

Deeply nested `and`/`or`/`not` trees are rejected at compile time (`> 100`
levels, `err.code === 'INVALID_CONDITION'`) so a pathological condition from a
store cannot exhaust the stack on the auth path.

### Temporal Expressions (`during`)

The [`during` operator](/accesscontrol/concepts/conditions/#temporal-scheduling--during)'s dtrexp expressions are bounded the same way: a length cap (> 1000 chars rejected, `err.code === 'INVALID_DTREXP'`), full validation at grant-commit time — malformed expressions throw `INVALID_DTREXP` with the parser's character position, and satisfiable-looking-but-never-matching ones throw `DTREXP_NEVER_MATCHES` — and a **bounded** parse cache (FIFO, 500 entries), so hostile serialized grants can neither reach the check path unvalidated nor grow memory through distinct expression strings. A non-date-like left side evaluates `false` (fail-closed), never throws.

## Error Messages & Information Disclosure

By default (`engine.safeErrors: true`) error **messages** omit caller‑supplied
values (names, the raw query/grants object) so request data doesn't leak into
logs. The values stay available programmatically.

```js
const e = grab(() => ac.can('ghost').readAny('post').granted);
e.message;  // "Role not found."   (redacted)
e.code;     // "ROLE_NOT_FOUND"
e.role;     // "ghost"             (structured field)
```

:::note[Branch on `err.code`, not on message text]
Messages are redacted and may change wording; [`err.code`](/accesscontrol/concepts/strict/#error-codes)
is the stable contract. Set `engine.safeErrors: false` for verbose `Got: …`
messages during development.
:::

Also return **uniform** responses for denials (same status/body) so
"doesn't exist" vs "denied" isn't observable to a client.

## Names & Homographs (Charset)

Names are restricted to ASCII `[A-Za-z0-9_-]` by default — which also rules out
Unicode **homograph** attacks (visually identical names with different code
points).

:::caution[Enabling `Charset.UNICODE` accepts homograph risk]
```js
import { Charset } from 'accesscontrol';
new AccessControl(grants, { engine: { charset: Charset.UNICODE } });
```
`аdmin` (Cyrillic `а`) becomes a *different* role from `admin` (Latin `a`). If
you enable Unicode names, **NFC‑normalize** them before use and consider
restricting to a single script. Structural characters (`/ : $ * !`) and the
reserved gadget names stay rejected in every mode.
:::

## Immutability

`getGrants()`, `getGrantsList()` and `getRequirements()` return **detached deep
copies** — mutating a result can never alter the live model or neuter a
`require()` gate. `lock()` deep‑freezes the model; after it, every mutator
throws `err.code === 'LOCKED'`. `Permission.attributes` / `.roles` are frozen
copies too.

## Timing Side-channels

Authorization isn't constant‑time (more roles/rules/conditions ⇒ more work). In
practice this is buried under network and DB latency, so it's effectively
unexploitable for server‑side checks — we treat constant‑time evaluation as a
non‑goal. If it's in your threat model: rate‑limit auth‑sensitive endpoints and
keep denial responses uniform.

## Supply Chain

The published package has **two runtime dependencies** — [`notation`](https://github.com/onury/notation) and [`dtrexp`](https://github.com/DTRExp/dtrexp-js) (the engine behind the `during` operator) — both from the same author, both pinned to exact versions, and there are **zero production advisories** (`npm audit --omit=dev`). Recommended for consumers:

```sh
npm audit --omit=dev    # audit only what actually ships
```

## What Testing Can and Cannot Prove

100% coverage and mutation testing prove the *written* code behaves; they cannot
prove the engine is safe against inputs the code never anticipated. AccessControl
therefore also ships:

- an **adversarial suite** (prototype gadgets, inherited‑key names, context
  spoofing, notation‑path pollution, lock/immutability, deny/wildcard leakage), and
- a **seeded property fuzzer** asserting engine invariants over thousands of
  random policies (determinism, possession cascade, multi‑role = union,
  serialization round‑trip, deny/require monotonicity, filter idempotence).

See [Quality & testing](/accesscontrol/best-practices/#quality--testing).
