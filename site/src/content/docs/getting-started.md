---
title: Getting Started
description: Install AccessControl and write your first grants and checks.
---

## Install

```sh
npm i accesscontrol
```

AccessControl v3 is **ESM** and ships TypeScript types.

```js
import { AccessControl } from 'accesscontrol';
```

### Other Runtimes

Because v3 is pure ESM with no Node-only built-in dependencies, it runs beyond
Node.js (≥ 20):

- **Bun** — works out of the box; install and import exactly as above:
  ```sh
  bun add accesscontrol
  ```
  ```js
  import { AccessControl } from 'accesscontrol';
  ```
- **Deno** — import via the `npm:` specifier (no install step):
  ```js
  import { AccessControl } from 'npm:accesscontrol';
  ```
  or pin a version: `npm:accesscontrol@^3`. If you keep an import map, add
  `"accesscontrol": "npm:accesscontrol@^3"` and `import { AccessControl } from 'accesscontrol'`.

The API is identical across runtimes — only the install/import line differs.

## Define Grants

Create roles with `grant()` / `deny()`, chaining as you go. Roles inherit others
with `extend()`; grants are additive and an explicit `deny` always wins.

```js
const ac = new AccessControl();

ac.grant('user')
    .createOwn('video')
    .deleteOwn('video')
    .readAny('video')
  .grant('admin')
    .extend('user')
    .updateAny('video', ['title'])   // only the `title` attribute
    .deleteAny('video');
```

## Check Permissions

```js
ac.can('user').createOwn('video').granted;     // true
ac.can('admin').updateAny('video').attributes; // ['title']
```

Use `filter()` to strip a record down to the allowed attributes:

```js
const perm = ac.can('user').readAny('video');
perm.filter(videoRecord); // only the granted fields
```

:::tip[On the request path, use `tryCan()`]
`can()` **throws** on an error (an unknown role under strict mode, invalid
input, …). `tryCan()` is identical but **never throws** — every failure resolves
to `granted: false`, so a forgotten `catch` can't turn an error into an
accidental *allow*.

```js
if (ac.tryCan(role).readAny('video').granted) show();
else deny();
```

Keep `can()` for boot/config and tests, where you *want* a typo to throw. See
[Best Practices](/accesscontrol/best-practices/#can-vs-trycan).
:::

## Add a Condition

Constrain a grant with `.where()`, and supply per-check data via the context.

```js
ac.grant('manager').where('$.order.value <= 100000').updateAny('order', ['*']);

ac.can('manager', { order: { value: 5000 } }).updateAny('order').granted; // true
```

## Enforce Ownership

Tell the engine how ownership is determined and pass the record — `own` checks
are then enforced:

```js
const ac = new AccessControl({}, { policy: { ownerField: 'ownerId' } });
ac.grant('user').updateOwn('order', ['*']);

ac.can('user', { user: { id: 7 }, order: { ownerId: 7 } }).updateOwn('order').granted; // true
ac.can('user', { user: { id: 7 }, order: { ownerId: 9 } }).updateOwn('order').granted; // false
```

## Next Steps

- **Concepts** (sidebar) — [Conditions](/accesscontrol/concepts/conditions/),
  [Ownership](/accesscontrol/concepts/ownership/),
  [Require Gates](/accesscontrol/concepts/gates/),
  [Groups & Categories](/accesscontrol/concepts/groups/),
  [Events & Auditing](/accesscontrol/concepts/events/), and more.
- [Best Practices](/accesscontrol/best-practices/) — `can` vs `tryCan`,
  `where` vs `require`, modelling ownership, locking.
- [Security Considerations](/accesscontrol/security/) — what's hardened and the
  choices left to you.
- [What's New in v3](/accesscontrol/whats-new/) ·
  [Migrating from v2](/accesscontrol/migration/) ·
  [FAQ](/accesscontrol/faq/)
- **API Reference** (sidebar) — generated from the library's types.
