---
title: Checking Access
description: Query the model with can / tryCan / check, read granted / attributes / reason, filter data, and resolve async checks.
---

Once grants are defined, you query them. There are a chainable form and a
one‑shot form, plus a fail‑closed variant.

## Chainable: `can()` / `tryCan()`

```js
const perm = ac.can('user').readAny('article');
perm.granted;     // boolean
perm.attributes;  // e.g. ['*', '!secret']
perm.roles;       // ['user']
perm.resource;    // 'article'
perm.action;      // 'read'  (bare verb; ':possession' suffix stripped)
perm.possession;  // 'any' | 'own'  (the possession that actually granted)
perm.filter(data) // data with only the allowed attributes
```

`possession` is **resolved**, not just echoed back: since `any` ⊇ `own`, a query
for `own` that's satisfied by an `any` grant reports `'any'` — so you can tell
*how* access was granted. On denial it reflects the requested possession.

Pass context as the second argument (or via `.with()`):

```js
ac.can('manager', { order }).updateAny('order');
ac.can('manager').with({ order }).updateAny('order');
```

:::tip[Use `tryCan()` on the request path]
`can()` **throws** on an error (invalid input, a `strict` violation, a `{ fn }`
condition on the sync path). `tryCan()` is identical but **never throws** — every
failure resolves to `granted: false`. Use it where a thrown error must not become
"allow". See [Best Practices › can vs tryCan](/accesscontrol/best-practices/#can-vs-trycan).

```js
if (ac.tryCan(role, ctx).readAny('article').granted) show();
else deny();
```
:::

## One-shot: `check()` / `checkAsync()`

When you already have a fulfilled query object:

```js
const perm = ac.check({
  role: 'user',
  resource: 'article',
  action: 'read:any',
  context: { /* … */ }
});
perm.granted;
```

## `granted` vs `attributes`

- `granted` — *whether* access is allowed (≥ 1 non‑negated attribute).
- `attributes` — *what fields* are allowed (glob notation).

```js
ac.grant('u').readAny('post', ['*', '!secret']);
ac.can('u').readAny('post').granted;     // true
ac.can('u').readAny('post').attributes;  // ['*', '!secret']

ac.grant('u').createAny('post', []);      // explicitly no attributes
ac.can('u').createAny('post').granted;    // false
```

## Filtering the Response

```js
const perm = ac.can('user').readOwn('account');
res.json(perm.filter(account));        // single object
res.json(perm.filter(accounts));        // array → maps over each
```

## Async Checks

A check whose applicable grant/gate uses a custom `{ fn }` condition must be
resolved with `grantedAsync` / `checkAsync`:

```js
const ok = await ac.can('admin', { ip })
  .readAny('server').grantedAsync;

const perm = await ac.checkAsync({
  role: 'admin', resource: 'server', action: 'read:any', context: { ip }
});
```

The sync `.granted` throws `ASYNC_REQUIRED` for such checks (or, under
`tryCan()`, denies). See [Async & Custom Functions](/accesscontrol/concepts/async/).

## Why a Check Might Be Denied

Subscribe to the [`access` event](/accesscontrol/concepts/events/) — every
resolved check (granted and denied) carries a `reason`
(`no_grant`, `condition_failed`, `ownership_failed`, `require_failed`).
