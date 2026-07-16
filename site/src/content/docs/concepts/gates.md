---
title: Require Gates
description: Mandatory restrictions with .require() at global, category and resource scope — they can only narrow access, never widen it.
---

`.require()` adds a **mandatory gate**: a condition that must pass for a check to
be granted, independent of any role's grants.

```
granted = (a grant matches) AND (every applicable gate passes)
```

:::note[Gates can only restrict]
Unlike [`.where()`](/accesscontrol/concepts/conditions/) (which conditionally
*grants*), a gate can never widen access — adding one can only take access away.
That makes gates the right tool for cross‑cutting rules.
:::

## Scopes

A gate applies at one of three scopes. On a check, the applicable gates are the
**global** ones, plus the resource's **category** gates, plus the **resource**
gates — all must pass.

```js
ac.require('$.env == "prod"');      // global: every check
ac.category('billing')
  .require('$.ip cidr 10.0.0.0/8'); // any billing/* resource
ac.resource('billing/invoice')
  .require('$.mfa == true');        // just billing/invoice
```

## Example: Layered Gates

```js
const ac = new AccessControl(grants, {
  context: { env: process.env.NODE_ENV }
});

ac.require('$.env == "prod"'); // 1) prod only
ac.category('billing').require('$.ip cidr 10.0.0.0/8'); // 2) + from the VPN
ac.resource('billing/invoice').require('$.mfa == true'); // 3) + MFA

// passes only if prod AND in-VPN AND mfa — on top of a matching grant
ac.can('accountant', { ip, mfa: true })
  .readAny('billing/invoice').granted;
```

A denial by a gate surfaces as `reason: 'require_failed'` on the
[`access` event](/accesscontrol/concepts/events/).

Gates take the same condition language as `.where()` — including [temporal schedules](/accesscontrol/concepts/conditions/#temporal-scheduling--during), which turn a gate into a time-box for a whole scope:

```js
// nothing under `billing` moves outside weekday business hours
ac.category('billing').require('$.now during "T0900:1800 E1:5"');
```

A gate that fails *only* on its schedule reports `reason: 'out_of_schedule'` instead of `'require_failed'` — the caller can distinguish "come back during access hours" from a hard policy denial. With multiple gates, the reason reflects the first failing gate (gates short-circuit).

## Missing Context — Gates Fail Closed

A gate's condition is evaluated against the check-time context. There is **no
separate "is this property present?" step** — a `$.`‑path that the context
doesn't supply simply resolves to `undefined`, and the operator runs against that.

For the common **positive assertion** this is exactly the behavior you want:

```js
ac.grant('admin').readAny('post', ['*']);
ac.require('$.env == "prod"');

ac.can('admin', { env: 'prod' }).readAny('post').granted; // true
ac.can('admin', { env: 'dev' }).readAny('post').granted;  // false
ac.can('admin', {}).readAny('post').granted;              // false  ← env missing
ac.can('admin').readAny('post').granted;                  // false  ← no context
```

With `env` absent, `$.env` is `undefined`, `undefined === 'prod'` is `false`, the
gate fails, and the check is **denied** (`reason: 'require_failed'`). A gate that
references data you forgot to pass denies rather than silently letting the request
through — **fail‑closed by construction**.

:::caution[A negated operator fails *open* on a missing property]
The fail‑closed guarantee comes from `==` (and the other positive operators)
comparing to `undefined`. A **negative** operator inverts that: with the property
absent, `undefined != 'dev'` is `true`, so the gate **passes**.

```js
ac.require('$.env != "dev"'); // "block dev"
ac.can('admin', {}).readAny('post').granted; // ⚠ true — env absent slips through
ac.can('admin', { env: 'dev' }).readAny('post').granted; // false
```

This is standard JavaScript comparison semantics, not a special case. For a
mandatory gate, prefer the **positive assertion** form (`$.env == "prod"`,
`$.mfa == true`, `$.ip cidr …`) so that *absence denies*. If you must use a
negative predicate, also assert presence — e.g.
`{ and: ['$.env != "dev"', '$.env in ["prod", "staging", "dev"]'] }`.
:::

The same resolution rule applies to [`.where()`](/accesscontrol/concepts/conditions/)
grant conditions — a missing path evaluates to a clean `false` (the grant simply
doesn't apply) and never throws. The security difference is directional: an absent
property makes a *grant* not apply and makes a positive *gate* deny — both
restrictive — while a negative gate is the one case where absence widens access.

## Inspecting Gates

```js
ac.getRequirements();
// { global: [...], categories: { billing: [...] }, resources: { 'billing/invoice': [...] } }
```

:::tip[The result is a detached copy]
`getRequirements()` returns a deep clone — mutating it cannot alter the live
gates. (A `require()` gate must not be neuterable through an introspection
result.)
:::

## Async Gates

A gate may use a custom `{ fn, args }` condition; like conditional grants, that
moves the check to the [async path](/accesscontrol/concepts/async/)
(`grantedAsync` / `checkAsync`).
