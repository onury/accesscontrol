---
title: Ownership
description: Make own actually mean owned — configure ownerField or a custom owner resolver, pass the record, and let the engine enforce it.
---

In v2, `readOwn` / `updateOwn` only chose *which attributes* applied —
confirming the record actually belonged to the user was **your** job. v3 can
**enforce** ownership for you.

## `ownerField` (the Convention)

Tell AccessControl which field holds the owner id, then pass both the user and
the record in the check context. Ownership is
`context.user.id === context.<resource>[ownerField]`.

```js
const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
ac.grant('user').updateOwn('order', ['*']);

ac.can('user', { user: { id: 7 }, order: { ownerId: 7 } })
  .updateOwn('order').granted; // true  (owned)

ac.can('user', { user: { id: 7 }, order: { ownerId: 9 } })
  .updateOwn('order').granted; // false (not owned)
```

## A Custom Resolver

For anything beyond a single field (composite keys, membership, async‑free
lookups against the context), provide `policy.owner(ctx)`. It **wins** over
`ownerField`.

```js
const ac = new AccessControl({}, {
  policy: {
    owner: (ctx) =>
      ctx.doc?.authorId === ctx.user?.id ||
      ctx.doc?.editors?.includes(ctx.user?.id)
  }
});
ac.grant('writer').updateOwn('doc', ['*', '!audit']);

ac.can('writer', { user, doc }).updateOwn('doc').granted;
```

:::note[`any` still satisfies `own`]
A blanket `any` grant covers an `own` check regardless of ownership — if you can
update *any* order, you can update your *own*.

```js
ac.grant('admin').updateAny('order', ['*']);
ac.can('admin', { user, order }).updateOwn('order').granted; // true
```
:::

## When Ownership Can't Be Verified

With a resolver configured but the record (or owner) missing from the context,
the check is **denied** under the default `strict.checks: true` — fail closed.

:::caution[Always load the record for `own` checks]
```js
// ❌ no record in context ⇒ unverifiable ⇒ denied (strict.checks default)
ac.can('user', { user }).updateOwn('order').granted; // false

// ✅ load it first
const order = await db.getOrder(id);
ac.can('user', { user, order }).updateOwn('order').granted;
```
Set `policy.strict.checks: false` to keep v2 behavior (resolve the `own`
attribute set and enforce ownership yourself). With **no** resolver configured
at all, `own` is never gated — existing v2 code isn't silently locked down.
:::

## Record-level Rules without Hand-rolled Checks

Express "can assign **own** folder to **any** user" as ownership + possession,
then let the engine decide:

```js
const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
ac.grant('user').createOwn('folderShare');   // own folder → any user
ac.grant('admin').createAny('folderShare');  // any folder → any user

const folder = await db.getFolder(folderId); // { ownerId: ... }
ac.can(role, { user, folderShare: folder })
  .createOwn('folderShare').granted;
```
