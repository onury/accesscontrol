---
title: Best Practices
description: Practical guidance for using AccessControl correctly — can vs tryCan, where vs require, modelling ownership, policy vs context, strict mode, locking, and the project's quality bar.
---

Short, opinionated guidance for the decisions that come up most often.

## `can` vs `tryCan`

Both query the same model. The difference is what happens on an **error**
(invalid input, a `strict` violation, an async‑required check on the sync path):
`can()` throws, `tryCan()` denies.

| Use | When |
| --- | --- |
| **`can()`** | Boot/config validation and tests — you *want* a typo or misconfiguration to throw loudly. |
| **`tryCan()`** | The request hot path — a failure must never become "allow". |

:::tip[Rule of thumb]
If a thrown error could be swallowed into an *allow*, use `tryCan()`. It makes
the fail‑closed intent visible at the call site.
:::

```js
// request handler — fail closed
if (!ac.tryCan(req.user.role, ctx).action(action, resource).granted) {
  return res.status(403).end();
}
```

```js
// startup smoke test — fail loud
ac.can('admin').readAny('report'); // throws if 'admin'/'report' are typos
```

Both `can()` and `tryCan()` still emit the `access` (and `error`) events, so
your audit log is identical either way.

## `where` vs `require`

- **`.where(condition)`** — a *conditional grant* (ABAC). It can only **add**
  access, under a condition.
- **`.require(condition)`** — a *mandatory gate*, independent of grants. It can
  only **restrict**: `granted = (a grant matches) AND (every applicable gate
  passes)`.

:::note
Reach for `require()` for cross‑cutting rules that must hold regardless of role
— "prod only", "inside the VPN", "MFA for billing". Reach for `where()` to give
a *specific* role conditional access.
:::

```js
ac.grant('manager')
  .where('$.order.value <= 100000') // managers, but only small orders
  .updateAny('order', ['*']);

ac.require('$.env == "prod"');      // everyone, every check, prod only
ac.category('billing')
  .require('$.ip cidr 10.0.0.0/8'); // billing/* only from the VPN
```

## Model Ownership, Don't Hand-roll It

If a rule is "the user owns the record", encode it as ownership + context, not as
an `if` next to the check. Configure it once, pass the record, let the engine
decide.

```js
const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
ac.grant('user').updateOwn('order', ['*']);

const order = await db.getOrder(id);   // { ownerId: ... }
ac.can('user', { user: req.user, order }).updateOwn('order').granted;
```

:::caution[An `own` grant without a record can't be verified]
With `ownerField`/`owner` configured, an `own` check whose context lacks the
record (or the owner) is **denied** under the default `strict.checks: true`.
Always load the record into the context for `own` checks. (Set
`strict.checks: false` to keep the v2 "select attributes, you enforce
ownership" behavior.)
:::

## Ship Booleans, Not the Policy

Access control runs on the **server**. The client should never receive your
grants — only *decisions*. Compute them with `tryCan()` (which never throws on
the view path) and send a small **capability map**:

```js
const caps = {
  canEditPost:   ac.tryCan(role).updateAny('post').granted,
  canSeeRevenue: ac.tryCan(role).readAny('dashboard:revenue').granted
};
res.json(caps); // the UI shows/hides from these flags
```

The client learns *what it can do*, not *how the policy is built*.

:::caution[UI gating is UX, not security]
Hiding a button is a usability nicety, not a boundary — a hidden control is
still reachable. **Always re-check on the server** when the action runs.
:::

**Don't**

- Never send `getGrants()` / `getGrantsList()` — or a single role's slice of
  them — to the browser.
- Never re-instantiate `AccessControl` in the client to "check locally". The
  policy leaks, and a client-side check can't be trusted anyway.

**Do**

- Decide on the server and send booleans (a capability map), or render
  server-side (SSR) so the markup arrives already gated.
- For a data-driven menu, model the surface as a **resource** and return only
  the allowed items:

  ```js
  ac.grant('guest').read('menu', ['home'])
    .grant('user').read('menu', ['home', 'profile', 'videos']);

  const items = ac.can(role).read('menu').attributes; // ['home','profile','videos']
  res.json(items); // client renders only these
  ```

:::note[This comes up a lot]
Related discussions: [#31](https://github.com/onury/accesscontrol/issues/31), [#62](https://github.com/onury/accesscontrol/issues/62), [#101](https://github.com/onury/accesscontrol/issues/101).
:::

## `engine` vs `policy` vs `context`

`new AccessControl(grants, { engine, policy, context })`. Three buckets, three
concerns — think **library**, **your domain**, **data**:

:::tip[Rule of thumb]
*If it's about the library's mechanics, it's `engine`. If it's about your
domain's authorization model, it's `policy`. If a condition reads it with `$.`,
it's `context`.*
:::

- **`engine`** — library mechanics & security: `pathPrefix`, `allowRegex`,
  `charset`, `safeErrors`, `errorCodePrefix`.
- **`policy`** — your authorization model: `ownerField`/`owner`, `strict`,
  action/resource allow‑lists.
- **`context`** — ambient data for conditions (`env`, `ip`, `user`, the record),
  merged with (and overridden by) the per‑check context from
  `can(role, context)` / `.with()`.

```js
const ac = new AccessControl(grants, {
  engine:  { allowRegex: false, charset: Charset.ASCII, safeErrors: true },
  policy:  { ownerField: 'ownerId', strict: { roles: true } },
  context: { env: process.env.NODE_ENV }
});
```

## Turn On Strict in Development

`strict.roles` is on by default (an unknown role throws). `actions` and
`resources` are **off** by default — an ungranted action/resource simply denies.
Turn them on while developing to catch typos, ideally with `setup()` declaring
your vocabulary so only true typos throw (a declared‑but‑ungranted name still
returns `granted:false`):

```js
const ac = new AccessControl(grants, {
  policy: { strict: { actions: true, resources: true } }
});
ac.setup({ actions: ['publish', 'approve'] }); // declare custom vocabulary
```

Pair this with `can()` (not `tryCan()`) in tests so the throw surfaces.

## Lock the Model After Building It

If your grants are fixed at boot, `lock()` the instance. It deep‑freezes the
model; any later mutation throws. This turns "someone mutated the policy at
runtime" from a possibility into an error.

```js
const ac = new AccessControl();
ac.grant('user').readAny('post', ['*', '!authorId']);
ac.grant('admin').extend('user').updateAny('post', ['*']);
ac.require('$.env == "prod"');

ac.lock(); // no more grant/deny/extend/setup/require/setGrants
```

## Persist as Rows, Rebuild on Boot

Store the flat list (DB‑friendly) and rehydrate; it round‑trips identically.

```js
await db.savePolicy(ac.getGrantsList()); // one row per rule + $extend rows
const ac = new AccessControl(await db.loadPolicy());
```

See [Serialization & Databases](/accesscontrol/concepts/serialization/).

## Quality & Testing

AccessControl is held to a high bar because a wrong answer here is a
vulnerability, not a bug:

- **100%** coverage (statements, branches, functions, lines).
- **Mutation tested** (Stryker, ≥ 88% and rising) — proves the *tests* actually
  catch regressions, not just execute lines.
- An **adversarial security suite** and a **seeded property fuzzer** assert
  invariants 100%/mutation can't (see [Security › What testing can and cannot
  prove](/accesscontrol/security/#what-testing-can-and-cannot-prove)).
- Zero production advisories (`npm audit --omit=dev`); single, pinned runtime
  dependency.
