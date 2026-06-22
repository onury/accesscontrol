---
title: Async & Custom Functions
description: Register business logic as JSON-serializable {fn, args} conditions and resolve them with grantedAsync / checkAsync.
---

Declarative conditions are synchronous. For business logic that needs I/O (a DB
lookup, an external service), register a **custom function** and reference it
from a grant or gate as `{ fn, args }` — the reference stays JSON‑serializable
(the function lives in code).

```js
ac.defineCondition('ipAllowed', async (ctx, args) =>
  isAllowed(ctx.ip, args.cidr)
);

ac.grant('admin')
  .where({ fn: 'ipAllowed', args: { cidr: '10.0.0.0/8' } })
  .readAny('server');
```

## Resolving on the async path

A check that touches a custom function must use the **async** accessors:

```js
const ok = await ac.can('admin', { ip })
  .readAny('server').grantedAsync;

// one-shot form
const perm = await ac.checkAsync({
  role: 'admin', resource: 'server', action: 'read:any', context: { ip }
});
perm.granted;
```

:::caution[The sync path throws for `{ fn }` conditions]
Calling `.granted` (sync) on a permission whose applicable rule/gate uses a
custom function throws `err.code === 'ASYNC_REQUIRED'` — a loud reminder to use
`grantedAsync` / `checkAsync`. On the request path,
[`tryCan()`](/accesscontrol/best-practices/#can-vs-trycan) turns that into a
plain denial instead.

```js
ac.can('admin', { ip }).readAny('server').granted;       // throws ASYNC_REQUIRED
await ac.tryCan('admin', { ip }).readAny('server').grantedAsync; // resolves
```
:::

## Declarative checks stay sync

Only `{ fn }` conditions require the async path. Purely declarative grants/gates
resolve synchronously even if you happen to `await` them, so you can use the
async accessors uniformly if you prefer.

```js
ac.grant('user').where('$.order.value <= 100').updateAny('order');
await ac.can('user', { order: { value: 50 } })
  .updateAny('order').grantedAsync; // works (declarative, but awaitable)
```

## Caching within a permission

Resolving a permission once memoizes its result: a sync resolve followed by an
`await` won't re‑resolve (and won't emit a second `access` event).

:::note[Custom functions and serialization]
Because only the **name + args** are stored in the grant, your model stays
JSON/DB‑serializable. Re‑register the functions with `defineCondition()` on the
instance that loads the model. An unknown function name fails closed with
`err.code === 'UNKNOWN_CONDITION_FN'`.
:::
